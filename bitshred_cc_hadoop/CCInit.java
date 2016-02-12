import java.io.*;
import java.io.IOException;
import java.util.*;
import java.net.URI;
import java.text.DecimalFormat;
import java.text.NumberFormat;

import org.apache.hadoop.fs.*;
import org.apache.hadoop.io.*;
import org.apache.hadoop.util.*;
import org.apache.hadoop.conf.*;
import org.apache.hadoop.mapreduce.*;
import org.apache.hadoop.mapreduce.lib.input.*;
import org.apache.hadoop.mapreduce.lib.output.*;

public class CCInit extends Configured implements Tool {
    private static int FP_SIZE = 1024*32;         // size of a fingerprint (in bytes)
    private final static int SHRED_SIZE = 16;     // size of a shred (in bytes)
    private final static int WINDOW_SIZE = 12;    // size of a window (Winnowing parameter)
    private final static int FP_PER_FILE = 2048;  // fingerprints per a file
    private final static String SAMPLE_PATH = "/user/jiyongj/unpacked/";        // path to malware samples
    private final static String DATA_PATH = "/user/jiyongj/cc/adjlist/data";    // path to fingerprints
    private final static String GLOBAL_PATH = "/user/jiyongj/cc/global/";       // path to r, c, G

    public static class Map extends Mapper<LongWritable, Text, IntWritable, RowStatWritable> {
        private static int numSamples;
        private static int numRowGroups;
        private static int numColGroups;

        private IntWritable bitShredKey;
        private RowStatWritable bitShredValue;
        private int rowLabel;
        private long[][] rowStat;
        private int[] rowSplitBoundary;
        private int[] colSplitBoundary;

        public void setup(Context context) {
            Configuration conf = context.getConfiguration();
            numSamples = Integer.parseInt(conf.get("my.numsamples"));
            numRowGroups = Integer.parseInt(conf.get("my.numrowgroups"));
            numColGroups = Integer.parseInt(conf.get("my.numcolgroups"));

            rowSplitBoundary = new int[numRowGroups-1];
            colSplitBoundary = new int[numColGroups-1];
            int numRowsPerGroup = numSamples/numRowGroups;
            int numColsPerGroup = (FP_SIZE*8)/numColGroups;
            Random rnd = new Random();
            int i;
            /*
            int numRowsPerGroup = (numSamples%numRowGroups==0) ? (numSamples/numRowGroups) : (numSamples/numRowGroups)+1;
            int numColsPerGroup = ((FP_SIZE*8)%numColGroups==0) ? ((FP_SIZE*8)/numColGroups) : ((FP_SIZE*8)/numColGroups)+1;
            */

            // Split randomly row/column groups
            for(i=0; i<numRowGroups-1; i++) {
                rowSplitBoundary[i] = rnd.nextInt(numRowsPerGroup-1)+(i*numRowsPerGroup)+1;
            }
            for(i=0; i<numColGroups-1; i++) {
                colSplitBoundary[i] = rnd.nextInt(numColsPerGroup-1)+(i*numColsPerGroup)+1;
            }
        }

        public void map(LongWritable key, Text value, Context context) throws IOException, InterruptedException {
            FileSystem fs = FileSystem.get(context.getConfiguration());
            int i,j,k;
            rowStat = new long[FP_PER_FILE][numColGroups];

            // adjacency list (fingerprints)
            // input range: 0,1,2,...,(numSamples/FP_PER_FILE-1)
            String line = value.toString();
            int tIndex = Integer.parseInt(line);
            Path dataPath = new Path(DATA_PATH+tIndex);
            FSDataInputStream in = fs.open(dataPath);
            byte[] bfBuf = new byte[FP_SIZE*FP_PER_FILE];
            in.read(0, bfBuf, 0, FP_SIZE*FP_PER_FILE);
            in.close();

            if (tIndex == (numSamples/FP_PER_FILE-1)) {
                // Write r (row group assignment) to disk
                int rLabel=0;
                Path globalRPath = new Path(GLOBAL_PATH+"r_"+Integer.toString(numRowGroups)+"_"+Integer.toString(numColGroups)+"_0");
                FSDataOutputStream out = fs.create(globalRPath);
                for(i=0; i<numSamples; i++) {
                    if(rLabel!=numRowGroups-1 && i>=rowSplitBoundary[rLabel]) {
                        rLabel++;
                    }
                    out.writeBytes(Integer.toString(rLabel));
                    if(i!=numSamples-1) {
                        out.writeBytes(",");
                    }
                }
                out.close();

                // Write number of row groups to disk
                Path globalNumRowGroupsPath = new Path(GLOBAL_PATH+"rnum_"+Integer.toString(numRowGroups)+"_"+Integer.toString(numColGroups)+"_0");
                out = fs.create(globalNumRowGroupsPath);
                out.writeBytes(Integer.toString(numRowGroups));
                out.close();

                // Write c (column group assignment) to disk
                int cLabel=0;
                Path globalCPath = new Path(GLOBAL_PATH+"c_"+Integer.toString(numRowGroups)+"_"+Integer.toString(numColGroups)+"_0");
                out = fs.create(globalCPath);
                for(i=0; i<FP_SIZE*8; i++) {
                    if(cLabel!=numColGroups-1 && i>=colSplitBoundary[cLabel]) {
                        cLabel++;
                    }
                    out.writeBytes(Integer.toString(cLabel));
                    if(i!=FP_SIZE*8-1) {
                        out.writeBytes(",");
                    }
                }
                out.close();

                // Write number of column groups to disk
                Path globalNumColGroupsPath = new Path(GLOBAL_PATH+"cnum_"+Integer.toString(numRowGroups)+"_"+Integer.toString(numColGroups)+"_0");
                out = fs.create(globalNumColGroupsPath);
                out.writeBytes(Integer.toString(numColGroups));
                out.close();
            }

            // Compute row statistics
            int byteIndex;
            rowLabel = 0;
            for(k=0; k<FP_PER_FILE; k++) {
                // getting a row label
                int offset = k*FP_SIZE;
                int sampleNumber = tIndex*FP_PER_FILE+k;
                for(i=rowLabel; i<numRowGroups-1; i++) {
                    if(sampleNumber<rowSplitBoundary[i]){
                        rowLabel = i;
                        break;
                    }
                }

                // getting a column label
                bitShredKey = new IntWritable(rowLabel);
                int colLabel = 0;
                for(i=0; i<FP_SIZE*8; i++) {
                    byteIndex = (int)(i >>> 3);
                    byte bitMask = (byte)(1 << ((int)i & 0x07));
                    if ((bfBuf[offset+byteIndex] & bitMask) != 0) {
                        for(j=colLabel; j<numColGroups-1; j++) {
                            if(i<colSplitBoundary[j]) {
                                colLabel = j;
                                break;
                            }
                        }
                        // updating row statistics
                        rowStat[k][colLabel] += 1;
                    }
                }
                // pass row statistics to REDUCE
                bitShredValue = new RowStatWritable(rowStat[k], sampleNumber);
                context.write(bitShredKey, bitShredValue);
            }
        }
    }

    public static class Reduce extends Reducer<IntWritable, RowStatWritable, IntWritable, RowStatWritable> {
        private static int numColGroups;
        private long[] rowStat;

        public void setup(Context context) {
            Configuration conf = context.getConfiguration();
            numColGroups = Integer.parseInt(conf.get("my.numcolgroups"));
        }

        public void reduce(IntWritable key, Iterable<RowStatWritable> values, Context context) throws IOException, InterruptedException {
            rowStat = new long[numColGroups];
            int rowLabel = key.get();
            long[] tmpStat;
            int tmpSample;
            int i;

            for (RowStatWritable tmpvalue : values) {
                tmpStat = tmpvalue.getRowStat();
                tmpSample = tmpvalue.getSampleNumber();
                for(i=0; i<numColGroups; i++) {
                    rowStat[i] += tmpStat[i];
                }
            }
            // Output row statistics
            context.write(key, new RowStatWritable(rowStat));
        }
    }

    public static class RowStatWritable implements Writable {
        private long[] rowStat;
        private int sampleNumber;

        public RowStatWritable() {
            this.rowStat = new long[0];
            this.sampleNumber = 0;
        }

        public RowStatWritable(long[] rowStat) {
            this.rowStat = rowStat;
            this.sampleNumber = 0;
        }

        public RowStatWritable(long[] rowStat, int sampleNumber) {
            this.rowStat = rowStat;
            this.sampleNumber = sampleNumber;
        }

        public void readFields(DataInput in) throws IOException {
            rowStat = new long[in.readInt()];
            for (int i=0; i<rowStat.length; i++) {
                rowStat[i] = in.readLong();
            }
            sampleNumber = in.readInt();
        }

        public void write(DataOutput out) throws IOException {
            out.writeInt(rowStat.length);
            for (int i=0; i<rowStat.length; i++) {
                out.writeLong(rowStat[i]);
            }
            out.writeInt(sampleNumber);
        }

        public long[] getRowStat() {
            return rowStat;
        }

        public int getSampleNumber() {
            return sampleNumber;
        }

        public String toString() {
            String str = "";
            for (int i=0; i<rowStat.length; i++) {
                str += Long.toString(rowStat[i]);
                if (i!=rowStat.length-1) {
                    str += ",";
                }
            }
            return str;
        }
    }

    public int run(String[] args) throws Exception {
        Configuration conf = new Configuration();
        conf.set("my.numsamples", args[0]);
        conf.set("my.numrowgroups", args[1]);
        conf.set("my.numcolgroups", args[2]);

        Job job = new Job(conf);
        job.setJarByClass(CCInit.class);
        job.setJobName("ccinit");

        job.setOutputKeyClass(IntWritable.class);
        job.setOutputValueClass(RowStatWritable.class);

        job.setMapperClass(Map.class);
        //conf.setCombinerClass(Reduce.class);
        job.setReducerClass(Reduce.class);
        job.setNumReduceTasks(1);

        job.setInputFormatClass(TextInputFormat.class);
        job.setOutputFormatClass(TextOutputFormat.class);

        FileInputFormat.setInputPaths(job, new Path(args[3]));
        FileOutputFormat.setOutputPath(job, new Path(args[4]));

        return job.waitForCompletion(true) ? 0 : 1;
    }

    public static void main(String[] args) throws Exception {
        int ret = ToolRunner.run(new CCInit(), args);
        System.exit(ret);
    }
}
