import java.io.*;
import java.io.IOException;
import java.util.*;
import java.net.URI;
import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.lang.Math;

import org.apache.hadoop.filecache.DistributedCache;
import org.apache.hadoop.fs.*;
import org.apache.hadoop.io.*;
import org.apache.hadoop.util.*;
import org.apache.hadoop.conf.*;
import org.apache.hadoop.mapreduce.*;
import org.apache.hadoop.mapreduce.lib.input.*;
import org.apache.hadoop.mapreduce.lib.output.*;

public class CCRow extends Configured implements Tool {
    private static int FP_SIZE = 1024*32;         // size of a fingerprint (in bytes)
    private final static int SHRED_SIZE = 16;     // size of a shred (in bytes)
    private final static int WINDOW_SIZE = 12;    // size of a window (Winnowing parameter)
    private final static int FP_PER_FILE = 2048;  // fingerprints per a file
    private final static String SAMPLE_PATH = "/user/jiyongj/unpacked/";        // path to malware samples
    private final static String DATA_PATH = "/user/jiyongj/cc/adjlist/data";    // path to fingerprints
    private final static String GLOBAL_PATH = "/user/jiyongj/cc/global/";       // path to r, c, G

    public static class Map extends Mapper<LongWritable, Text, IntWritable, RowStatWritable> {
        private static int numSamples;
        private static int numInitRowGroups;
        private static int numInitColGroups;
        private static int numCurRowGroups;
        private static int numCurColGroups;

        private IntWritable bitShredKey;
        private RowStatWritable bitShredValue;

        private long[][] globalG;
        private int[] globalR;
        private int[] globalC;
        private int[] numColsInEachGroup;
        private int[] numRowsInEachGroup;
        private long[][] rowStat;

        private Path[] localFiles;
        private FileSystem lfs;
        private FileSystem fs;

        public void setup(Context context) {
            Configuration conf = context.getConfiguration();
            try {
                lfs = FileSystem.getLocal(conf);
                localFiles = DistributedCache.getLocalCacheFiles(conf);
            } catch (IOException ioe) {
                System.err.println("Caught exception while getting cached files");
            }
            numSamples = Integer.parseInt(conf.get("my.numsamples"));
            numInitRowGroups = Integer.parseInt(conf.get("my.numinitrowgroups"));
            numInitColGroups = Integer.parseInt(conf.get("my.numinitcolgroups"));
            numCurRowGroups = Integer.parseInt(conf.get("my.numcurrowgroups"));
            numCurColGroups = Integer.parseInt(conf.get("my.numcurcolgroups"));
        }

        public void map(LongWritable key, Text value, Context context) throws IOException, InterruptedException {
            fs = FileSystem.get(context.getConfiguration());
            globalG = new long[numCurRowGroups][numCurColGroups];
            globalR = new int[numSamples];
            globalC = new int[FP_SIZE*8];
            numColsInEachGroup = new int[numCurColGroups];
            numRowsInEachGroup = new int[numCurRowGroups];
            int i,j,k,index;

            // Initialize global parameters, e.g., r, c, G
            FSDataInputStream in = lfs.open(localFiles[0]);
            LineReader reader = new LineReader(in); 
            Text str = new Text();
            StringTokenizer st;
            while((reader.readLine(str))!=0) {
                st = new StringTokenizer(str.toString());
                int rLabel = Integer.parseInt(st.nextToken());
                String g = st.nextToken();
                st = new StringTokenizer(g, ",");
                int cLabel = 0;
                while(st.hasMoreTokens()) {
                     globalG[rLabel][cLabel] = Long.parseLong(st.nextToken());
                     cLabel++;
                }
            }
            reader.close();
            in.close();

            in = lfs.open(localFiles[1]);
            reader = new LineReader(in);
            reader.readLine(str);
            st = new StringTokenizer(str.toString(), ",");
            index = 0;
            while(st.hasMoreTokens()) {
                globalR[index] = Integer.parseInt(st.nextToken());
                index++;
            }
            reader.close();
            in.close();

            in = lfs.open(localFiles[2]);
            reader = new LineReader(in);
            reader.readLine(str);
            st = new StringTokenizer(str.toString(), ",");
            index = 0;
            while(st.hasMoreTokens()) {
                globalC[index] = Integer.parseInt(st.nextToken());
                index++;
            }
            reader.close();
            in.close();

            for(i=0; i<globalC.length; i++) {
                numColsInEachGroup[globalC[i]] += 1;
            }
            for(i=0; i<globalR.length; i++) {
                numRowsInEachGroup[globalR[i]] += 1;
            }

            // Load adjacency list (fingerprints)
            String line = value.toString();
            int tIndex = Integer.parseInt(line);
            Path dataPath = new Path(DATA_PATH+tIndex);
            in = fs.open(dataPath);
            byte[] bfBuf = new byte[FP_SIZE*FP_PER_FILE];
            in.read(0, bfBuf, 0, FP_SIZE*FP_PER_FILE);
            in.close();
            
            // Compute row statistics
            rowStat = new long[FP_PER_FILE][numCurColGroups];
            int byteIndex;
            for(k=0; k<FP_PER_FILE; k++) {
                context.progress();
                int offset = k*FP_SIZE;
                int sampleNumber = tIndex*FP_PER_FILE+k;
                for(i=0; i<FP_SIZE*8; i++) {
                    byteIndex = (int)(i >>> 3);
                    byte bitMask = (byte)(1 << ((int)i & 0x07));
                    if ((bfBuf[offset+byteIndex] & bitMask) != 0) {
                        rowStat[k][globalC[i]] += 1;
                    }
                }

                // Assign a sample to the row group such that lowers cost
                int curRLabel = globalR[sampleNumber];
                bitShredKey = new IntWritable(OptRowGroup(curRLabel, k));
                bitShredValue = new RowStatWritable(rowStat[k], sampleNumber);
                context.write(bitShredKey, bitShredValue);
            }
        }

        /*
         *  For every row, the function takes as inputs current row label and prospective row label.
         *  Then, the function returns the difference in code length between before and after moving the row.
         *  Main program will iterate over all possible prospective row labels and select the row label
         *  minimizing the code length.
        */
        private int OptRowGroup(int curRLabel, int index) {
            int i;
            int proRLabel;
            int numCurRow;
            int numProRow;
            int numCol;
            long num1;
            long num0;

            float beforeCost = 0;
            float afterCost = 0;
            float minCost;
            float tmpCost;
            float cost;
            int minRLabel;

            numCurRow = numRowsInEachGroup[curRLabel];

            for(i=0; i<numCurColGroups; i++) {
                numCol = numColsInEachGroup[i];
                num1 = globalG[curRLabel][i];
                num0 = (long)numCurRow*numCol - num1;
                if (num1!=0 && num0!=0)
                    beforeCost += num1*Math.log((num1+num0)/(float)num1) + num0*Math.log((num1+num0)/(float)num0);
                num1 = globalG[curRLabel][i] - rowStat[index][i];
                num0 = (long)(numCurRow-1)*numCol - num1;
                if (num1!=0 && num0!=0)
                    afterCost += num1*Math.log((num1+num0)/(float)num1) + num0*Math.log((num1+num0)/(float)num0);
            }
            tmpCost = afterCost - beforeCost;

            minCost = 0;
            minRLabel = curRLabel;
            for(proRLabel=0; proRLabel<numCurRowGroups; proRLabel++) {
                if (proRLabel==curRLabel) continue;
                numProRow = numRowsInEachGroup[proRLabel];
                beforeCost = 0;
                afterCost = 0;

                for(i=0; i<numCurColGroups; i++) {
                    numCol = numColsInEachGroup[i];
                    num1 = globalG[proRLabel][i];
                    num0 = (long)numProRow*numCol - num1;
                    if (num1!=0 && num0!=0)
                        beforeCost += num1*Math.log((num1+num0)/(float)num1) + num0*Math.log((num1+num0)/(float)num0);
                    num1 = globalG[proRLabel][i] + rowStat[index][i];
                    num0 = (long)(numProRow+1)*numCol - num1;
                    if (num1!=0 && num0!=0)
                        afterCost += num1*Math.log((num1+num0)/(float)num1) + num0*Math.log((num1+num0)/(float)num0);
                }
                cost = tmpCost + (afterCost - beforeCost);

                if(cost < minCost) {
                    minRLabel = proRLabel;
                    minCost = cost;
                }
            }
            return minRLabel;
        }
    }

    public static class Reduce extends Reducer<IntWritable, RowStatWritable, IntWritable, RowStatWritable> {
        private static int numSamples;
        private static int numInitRowGroups;
        private static int numInitColGroups;
        private static int numCurRowGroups;
        private static int numCurColGroups;
        private static int numCurIter;
        private long[] rowStat;
        private int[] globalR;

        private int realRowLabel = 0;
        protected static enum MyCounter {
            NUM_RECORDS
        };
        private int counter;

        public void setup(Context context) {
            Configuration conf = context.getConfiguration();
            numSamples = Integer.parseInt(conf.get("my.numsamples"));
            numInitRowGroups = Integer.parseInt(conf.get("my.numinitrowgroups"));
            numInitColGroups = Integer.parseInt(conf.get("my.numinitcolgroups"));
            numCurRowGroups = Integer.parseInt(conf.get("my.numcurrowgroups"));
            numCurColGroups = Integer.parseInt(conf.get("my.numcurcolgroups"));
            numCurIter = Integer.parseInt(conf.get("my.numiteration"));
            globalR = new int[numSamples];
        }

        public void reduce(IntWritable key, Iterable<RowStatWritable> values, Context context) throws IOException, InterruptedException {
            rowStat = new long[numCurColGroups];
            long[] tmpStat;
            int tmpSample;
            int i;

            int rowLabel = key.get();
            for (RowStatWritable tmpvalue : values) {
                context.getCounter(MyCounter.NUM_RECORDS).increment(1);
                tmpStat = tmpvalue.getRowStat();
                tmpSample = tmpvalue.getSampleNumber();
                globalR[tmpSample] = realRowLabel;
                for(i=0; i<numCurColGroups; i++) {
                    rowStat[i] += tmpStat[i];
                }
            }
            context.write(new IntWritable(realRowLabel), new RowStatWritable(rowStat));
            realRowLabel++;
            
            counter = (int) context.getCounter(MyCounter.NUM_RECORDS).getValue();
            if(counter==numSamples) {
                // Write updated r (row group assignment)
                FileSystem fs = FileSystem.get(context.getConfiguration());
                Path globalRPath = new Path(GLOBAL_PATH+"r_"+Integer.toString(numInitRowGroups)+"_"+Integer.toString(numInitColGroups)+"_"+Integer.toString(numCurIter));
                FSDataOutputStream out = fs.create(globalRPath);
                for(i=0; i<numSamples; i++) {
                    out.writeBytes(Integer.toString(globalR[i]));
                    if(i!=numSamples-1) {
                        out.writeBytes(",");
                    }
                }
                out.close();

                // Write updated number of row groups
                Path globalNumRowGroupsPath = new Path(GLOBAL_PATH+"rnum_"+Integer.toString(numInitRowGroups)+"_"+Integer.toString(numInitColGroups)+"_"+Integer.toString(numCurIter));
                out = fs.create(globalNumRowGroupsPath);
                out.writeBytes(Integer.toString(realRowLabel));
                out.close();
            }
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
        conf.set("my.numinitrowgroups", args[1]);
        conf.set("my.numinitcolgroups", args[2]);
        conf.set("my.numiteration", args[3]);

        int numCurIter = Integer.parseInt(args[3]);

        // Load the latest r, c, G
        DistributedCache.addCacheFile(new URI("/user/jiyongj/cc/global/g_"+args[1]+"_"+args[2]+"_"+Integer.toString(numCurIter-1)), conf);
        DistributedCache.addCacheFile(new URI("/user/jiyongj/cc/global/r_"+args[1]+"_"+args[2]+"_"+Integer.toString(numCurIter-1)), conf);
        DistributedCache.addCacheFile(new URI("/user/jiyongj/cc/global/c_"+args[1]+"_"+args[2]+"_"+Integer.toString(numCurIter-1)), conf);

        FileSystem fs = FileSystem.get(conf);
        Path globalNumRowGroupsPath = new Path(CCRow.GLOBAL_PATH+"rnum_"+args[1]+"_"+args[2]+"_"+Integer.toString(numCurIter-1));
        FSDataInputStream in = fs.open(globalNumRowGroupsPath);
        LineReader reader = new LineReader(in);
        Text str = new Text();
        reader.readLine(str);
        conf.set("my.numcurrowgroups", str.toString());
        reader.close();
        in.close();

        Path globalNumColGroupsPath = new Path(CCRow.GLOBAL_PATH+"cnum_"+args[1]+"_"+args[2]+"_"+Integer.toString(numCurIter-1));
        in = fs.open(globalNumColGroupsPath);
        reader = new LineReader(in);
        reader.readLine(str);
        conf.set("my.numcurcolgroups", str.toString());
        reader.close();
        in.close();

        Job job = new Job(conf);
        job.setJarByClass(CCRow.class);
        job.setJobName("ccrow");

        job.setOutputKeyClass(IntWritable.class);
        job.setOutputValueClass(RowStatWritable.class);

        job.setMapperClass(Map.class);
        //job.setCombinerClass(Reduce.class);
        job.setReducerClass(Reduce.class);
        job.setNumReduceTasks(1);

        job.setInputFormatClass(TextInputFormat.class);
        job.setOutputFormatClass(TextOutputFormat.class);

        FileInputFormat.setInputPaths(job, new Path(args[4]));
        FileOutputFormat.setOutputPath(job, new Path(args[5]));

        return job.waitForCompletion(true) ? 0 : 1;
    }

    public static void main(String[] args) throws Exception {
        int ret = ToolRunner.run(new CCRow(), args);
        System.exit(ret);
    }
}

