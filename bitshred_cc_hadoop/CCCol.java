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

public class CCCol extends Configured implements Tool {
    private static int FP_SIZE = 1024*32;         // size of a fingerprint (in bytes)
    private final static int SHRED_SIZE = 16;     // size of a shred (in bytes)
    private final static int WINDOW_SIZE = 12;    // size of a window (Winnowing parameter)
    private final static int FP_PER_FILE = 2048;  // fingerprints per a file
    private final static String SAMPLE_PATH = "/user/jiyongj/unpacked/";        // path to malware samples
    private final static String DATA_PATH = "/user/jiyongj/cc/adjlist/data";    // path to fingerprints
    private final static String GLOBAL_PATH = "/user/jiyongj/cc/global/";       // path to r, c, G

    public static class Map extends Mapper<LongWritable, Text, IntWritable, RowStatWritable> {
        private static int numSamples;
        private static int numInitTRowGroups;
        private static int numInitTColGroups;
        private static int numCurTRowGroups;
        private static int numCurTColGroups;
        
        private IntWritable bitShredKey;
        private RowStatWritable bitShredValue;

        private long[][] globalTG;
        private int[] globalTC;
        private int[] globalTR;
        private int[] numTColsInEachGroup;
        private int[] numTRowsInEachGroup;
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
            numInitTColGroups = Integer.parseInt(conf.get("my.numinitrowgroups")); // now Transpose matrix
            numInitTRowGroups = Integer.parseInt(conf.get("my.numinitcolgroups")); // now Transpose matrix
            numCurTColGroups = Integer.parseInt(conf.get("my.numcurrowgroups"));   // now Transpose matrix
            numCurTRowGroups = Integer.parseInt(conf.get("my.numcurcolgroups"));   // now Transpose matrix
        }

        public void map(LongWritable key, Text value, Context context) throws IOException, InterruptedException {
            fs = FileSystem.get(new Configuration());
            globalTG = new long[numCurTRowGroups][numCurTColGroups];
            globalTC = new int[numSamples];
            globalTR = new int[FP_SIZE*8];
            numTColsInEachGroup = new int[numCurTColGroups];
            numTRowsInEachGroup = new int[numCurTRowGroups];
            int i,j,k,index;

            // Initialize global parameters, e.g., r, c, G
            FSDataInputStream in = lfs.open(localFiles[0]);
            LineReader reader = new LineReader(in);
            Text str = new Text();
            StringTokenizer st;
            while((reader.readLine(str))!=0) {
                st = new StringTokenizer(str.toString());
                int cLabel = Integer.parseInt(st.nextToken());
                String g = st.nextToken();
                st = new StringTokenizer(g, ",");
                int rLabel = 0;
                while(st.hasMoreTokens()) {
                     globalTG[rLabel][cLabel] = Long.parseLong(st.nextToken());
                     rLabel++;
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
                globalTC[index] = Integer.parseInt(st.nextToken()); 
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
                globalTR[index] = Integer.parseInt(st.nextToken()); 
                index++;
            }
            reader.close();
            in.close();

            for(i=0; i<globalTC.length; i++) {
                numTColsInEachGroup[globalTC[i]] += 1;
            }
            for(i=0; i<globalTR.length; i++) {
                numTRowsInEachGroup[globalTR[i]] += 1;
            }

            // Load row statistics for Transpose matrix of adjacency list (fingerprint)
            // input range: 0,1,2,...,(FP_SIZE*8/statBlockSize-1) 
            int statBlockSize = 4096;
            String line = value.toString();
            int tIndex = Integer.parseInt(line);
            rowStat = new long[statBlockSize][numCurTColGroups];
            byte[] bfBuf = new byte[FP_SIZE*FP_PER_FILE];
            int byteIndex;
            for(i=0; i<(numSamples/FP_PER_FILE); i++) {
                context.progress();
                Path dataPath = new Path(DATA_PATH+i);
                in = fs.open(dataPath);
                in.read(0, bfBuf, 0, FP_SIZE*FP_PER_FILE);
                in.close();
                for(k=0; k<FP_PER_FILE; k++) {
                    int offset = k*FP_SIZE+(statBlockSize/8)*tIndex;
                    for(j=0; j<statBlockSize; j++) {
                        byteIndex = (int)(j >>> 3);
                        byte bitMask = (byte)(1 << ((int)j & 0x07));
                        if ((bfBuf[offset+byteIndex] & bitMask) != 0) {
                            rowStat[j][globalTC[i*FP_PER_FILE+k]] += 1;
                        }
                    }
                }
            }

            for(i=0; i<statBlockSize; i++) {
                int sampleNumber = tIndex*statBlockSize+i;
                int curTRLabel = globalTR[sampleNumber];

                // Assign a sample to the row group such that lowers cost
                bitShredKey = new IntWritable(OptTRowGroup(curTRLabel, i));
                bitShredValue = new RowStatWritable(rowStat[i], sampleNumber);
                context.write(bitShredKey, bitShredValue);
            }
        }

        /*
         *  For every row, the function takes as inputs current row label and prospective row label.
         *  Then, the function returns the difference in code length between before and after moving the row.
         *  Main program will iterate over all possible prospective row labels and select the row label
         *  minimizing the code length.
        */
        private int OptTRowGroup(int curTRLabel, int index) {
            int i;
            int proTRLabel;
            int numCurTRow;
            int numProTRow;
            int numTCol;
            long num1;
            long num0;

            float beforeCost = 0;
            float afterCost = 0;
            float minCost;
            float tmpCost;
            float cost;
            int minTRLabel;

            numCurTRow = numTRowsInEachGroup[curTRLabel];

            for(i=0; i<numCurTColGroups; i++) {
                numTCol = numTColsInEachGroup[i];
                num1 = globalTG[curTRLabel][i];
                num0 = (long)numCurTRow*numTCol - num1;
                if (num1!=0 && num0!=0)
                    beforeCost += num1*Math.log((num1+num0)/(float)num1) + num0*Math.log((num1+num0)/(float)num0);
                num1 = globalTG[curTRLabel][i] - rowStat[index][i];
                num0 = (long)(numCurTRow-1)*numTCol - num1;
                if (num1!=0 && num0!=0)
                    afterCost += num1*Math.log((num1+num0)/(float)num1) + num0*Math.log((num1+num0)/(float)num0);
            }
            tmpCost = afterCost - beforeCost;

            minCost = 0;
            minTRLabel = curTRLabel;
            for(proTRLabel=0; proTRLabel<numCurTRowGroups; proTRLabel++) {
                if (proTRLabel==curTRLabel) continue;
                numProTRow = numTRowsInEachGroup[proTRLabel];
                beforeCost = 0;
                afterCost = 0;

                for(i=0; i<numCurTColGroups; i++) {
                    numTCol = numTColsInEachGroup[i];
                    num1 = globalTG[proTRLabel][i];
                    num0 = (long)numProTRow*numTCol - num1;
                    if (num1!=0 && num0!=0)
                        beforeCost += num1*Math.log((num1+num0)/(float)num1) + num0*Math.log((num1+num0)/(float)num0);
                    num1 = globalTG[proTRLabel][i] + rowStat[index][i];
                    num0 = (long)(numProTRow+1)*numTCol - num1;
                    if (num1!=0 && num0!=0)
                        afterCost += num1*Math.log((num1+num0)/(float)num1) + num0*Math.log((num1+num0)/(float)num0);
                }
                cost = tmpCost + (afterCost - beforeCost);

                if(cost < minCost) {
                    minTRLabel = proTRLabel;
                    minCost = cost;
                }
            }
            return minTRLabel;
        }
    }

    public static class Reduce extends Reducer<IntWritable, RowStatWritable, IntWritable, RowStatWritable> {
        private static int numSamples;
        private static int numInitTColGroups;
        private static int numInitTRowGroups;
        private static int numCurTColGroups;
        private static int numCurTRowGroups;
        private static int numCurIter;

        private long[] rowStat;
        private long[][] globalTG;
        private int[] globalTR;
        private int[] globalTC;
        private int[] numTColsInEachGroup;
        private int[] numTRowsInEachGroup;
        protected static enum MyCounter {
            NUM_RECORDS
        };
        private int counter;

        private Path[] localFiles;
        private FileSystem lfs;
        private FileSystem fs;

        private int realTRowLabel = 0;
        private long[] outRowStat;

        public void setup(Context context) {
            Configuration conf = context.getConfiguration();
            try {
                lfs = FileSystem.getLocal(conf);
                localFiles = DistributedCache.getLocalCacheFiles(conf);
            } catch (IOException ioe) {
                System.err.println("Caught exception while getting cached files");
            }
            numSamples = Integer.parseInt(conf.get("my.numsamples"));
            numInitTColGroups = Integer.parseInt(conf.get("my.numinitrowgroups")); // now Transpose matrix
            numInitTRowGroups = Integer.parseInt(conf.get("my.numinitcolgroups")); // now Transpose matrix
            numCurTColGroups = Integer.parseInt(conf.get("my.numcurrowgroups"));   // now Transpose matrix
            numCurTRowGroups = Integer.parseInt(conf.get("my.numcurcolgroups"));   // now Transpose matrix
            numCurIter = Integer.parseInt(conf.get("my.numiteration"));
            globalTG = new long[numCurTRowGroups][numCurTColGroups];
            globalTC = new int[numSamples];
            globalTR = new int[FP_SIZE*8];
        }

        public void reduce(IntWritable key, Iterable<RowStatWritable> values, Context context) throws IOException, InterruptedException {
            rowStat = new long[numCurTColGroups];
            long[] tmpStat;
            int tmpSample;
            int i,j;

            int rowTLabel = key.get();
            for (RowStatWritable tmpvalue : values) {
                context.getCounter(MyCounter.NUM_RECORDS).increment(1);
                tmpStat = tmpvalue.getRowStat();
                tmpSample = tmpvalue.getSampleNumber();
                globalTR[tmpSample] = realTRowLabel;
                for(i=0; i<numCurTColGroups; i++) {
                    rowStat[i] += tmpStat[i];
                }
            }
            for(i=0; i<numCurTColGroups; i++) {
                globalTG[realTRowLabel][i] = rowStat[i];
            }
            realTRowLabel++;

            counter = (int) context.getCounter(MyCounter.NUM_RECORDS).getValue();
            if(counter==FP_SIZE*8) {
                // Write updated c (column group assignment)
                fs = FileSystem.get(new Configuration());
                Path globalTRPath = new Path(GLOBAL_PATH+"c_"+Integer.toString(numInitTColGroups)+"_"+Integer.toString(numInitTRowGroups)+"_"+Integer.toString(numCurIter));
                FSDataOutputStream out = fs.create(globalTRPath);
                for(i=0; i<FP_SIZE*8; i++) {
                    out.writeBytes(Integer.toString(globalTR[i]));
                    if(i!=FP_SIZE*8-1) {
                        out.writeBytes(",");
                    }
                }
                out.close();

                // Write updated number of column groups
                Path globalNumTRowGroupsPath = new Path(GLOBAL_PATH+"cnum_"+Integer.toString(numInitTColGroups)+"_"+Integer.toString(numInitTRowGroups)+"_"+Integer.toString(numCurIter));
                out = fs.create(globalNumTRowGroupsPath);
                out.writeBytes(Integer.toString(realTRowLabel));
                out.close();
                numCurTRowGroups = realTRowLabel;

                FSDataInputStream in = lfs.open(localFiles[1]);
                LineReader reader = new LineReader(in);
                Text str = new Text();
                reader.readLine(str);
                StringTokenizer st = new StringTokenizer(str.toString(), ",");
                int index = 0;
                while(st.hasMoreTokens()) {
                    globalTC[index] = Integer.parseInt(st.nextToken()); 
                    index++;
                }
                reader.close();
                in.close();

                numTColsInEachGroup = new int[numCurTColGroups];
                for(i=0; i<globalTC.length; i++) {
                    numTColsInEachGroup[globalTC[i]] += 1;
                }
                numTRowsInEachGroup = new int[numCurTRowGroups];
                for(i=0; i<globalTR.length; i++) {
                    numTRowsInEachGroup[globalTR[i]] += 1;
                }

                // Write the total cost (code length)
                Path globalCostPath = new Path(GLOBAL_PATH+"cost_"+Integer.toString(numInitTColGroups)+"_"+Integer.toString(numInitTRowGroups)+"_"+Integer.toString(numCurIter));
                out = fs.create(globalCostPath);
                out.writeBytes(Float.toString(TotalCodeLength()));
                out.close();

                outRowStat = new long[numCurTRowGroups];
                for(i=0; i<numCurTColGroups; i++) {
                    for(j=0; j<numCurTRowGroups; j++) {
                        outRowStat[j] = globalTG[j][i];
                    }
                    context.write(new IntWritable(i), new RowStatWritable(outRowStat));
                }
            }
        }

        private float TotalCodeLength() {
            int i,j;
            int numTRow;
            int numTCol;
            long num1;
            long num0;

            float cost = 0;

            for(i=0; i<numCurTRowGroups; i++) {
                numTRow = numTRowsInEachGroup[i];
                for(j=0; j<numCurTColGroups; j++) {
                    numTCol = numTColsInEachGroup[j];

                    num1 = globalTG[i][j];
                    num0 = (long)numTRow*numTCol - num1;
                    if (num1!=0 && num0!=0)
                        cost += num1*Math.log((num1+num0)/(float)num1) + num0*Math.log((num1+num0)/(float)num0);
                }
            }
            return cost;
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
        DistributedCache.addCacheFile(new URI("/user/jiyongj/cc/global/g_"+args[1]+"_"+args[2]+"_"+Integer.toString(numCurIter)+"_row"), conf);
        DistributedCache.addCacheFile(new URI("/user/jiyongj/cc/global/r_"+args[1]+"_"+args[2]+"_"+Integer.toString(numCurIter)), conf);
        DistributedCache.addCacheFile(new URI("/user/jiyongj/cc/global/c_"+args[1]+"_"+args[2]+"_"+Integer.toString(numCurIter-1)), conf);

        FileSystem fs = FileSystem.get(new Configuration());
        Path globalNumRowGroupsPath = new Path(CCCol.GLOBAL_PATH+"rnum_"+args[1]+"_"+args[2]+"_"+Integer.toString(numCurIter));
        FSDataInputStream in = fs.open(globalNumRowGroupsPath);
        LineReader reader = new LineReader(in);
        Text str = new Text();
        reader.readLine(str);
        conf.set("my.numcurrowgroups", str.toString());
        reader.close();
        in.close();

        Path globalNumColGroupsPath = new Path(CCCol.GLOBAL_PATH+"cnum_"+args[1]+"_"+args[2]+"_"+Integer.toString(numCurIter-1));
        in = fs.open(globalNumColGroupsPath);
        reader = new LineReader(in);
        reader.readLine(str);
        conf.set("my.numcurcolgroups", str.toString());
        in.close();

        Job job = new Job(conf);
        job.setJarByClass(CCCol.class);
        job.setJobName("cccol");

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
        int ret = ToolRunner.run(new CCCol(), args);
        System.exit(ret);
    }
}

