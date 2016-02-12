import java.io.IOException;
import java.util.*;
import java.net.URI;
import java.text.DecimalFormat;
import java.text.NumberFormat;

import org.apache.hadoop.filecache.DistributedCache;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FSDataOutputStream;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.conf.*;
import org.apache.hadoop.io.*;
import org.apache.hadoop.mapred.*;
import org.apache.hadoop.util.*;

public class Cmp {

    public static class Map extends MapReduceBase implements Mapper<LongWritable, Text, Text, Text> {
        private final static int BF_SIZE = 1024*32;
        private final static int BF_PER_FILE = 2048;
        //private int numBF = 501760;
        private int numBF = 512000;
        private int numData = numBF/BF_PER_FILE;
        private Text bitShredKey = new Text();
        private Text bitShredValue = new Text();

        private Path[] localFiles;
        private final static String DATA_PATH = "/user/jiyongj/bf/data";
        //FSDataInputStream[] in = new FSDataInputStream[numBF/BF_PER_FILE];

//        public void configure(JobConf job) {
//            try {
//                fs = FileSystem.getLocal(new Configuration());
//                localFiles = DistributedCache.getLocalCacheFiles(job);
//            } catch (IOException ioe) {
//                System.err.println("Caught exception while getting cached files");
//            }
//        }

        public void map(LongWritable key, Text value, OutputCollector<Text, Text> output, Reporter reporter) throws IOException {
            FileSystem fs = FileSystem.get(new Configuration());
            float jaccard;
            NumberFormat formatter = new DecimalFormat("#.######");

            String line = value.toString();
            StringTokenizer st = new StringTokenizer(line);
            int dataFileV = Integer.parseInt(st.nextToken());
            int dataFileH;
            //int dataFileH = Integer.parseInt(st.nextToken());
            int fileV, fileH;
            int fileNumberV, fileNumberH;

            
            FSDataInputStream inV = fs.open(new Path(DATA_PATH+Integer.toString(dataFileV)));
            byte[] bfBufV = new byte[BF_SIZE*BF_PER_FILE];
            inV.read(0, bfBufV, 0, BF_SIZE*BF_PER_FILE);
            inV.close();

            for(dataFileH=dataFileV; dataFileH<numData; dataFileH++) {
                if (dataFileV != dataFileH) {
                    FSDataInputStream inH = fs.open(new Path(DATA_PATH+Integer.toString(dataFileH)));
                    //FSDataInputStream inH = fs.open(localFiles[dataFileH]);
                    byte[] bfBufH = new byte[BF_SIZE*BF_PER_FILE];
                    inH.read(0, bfBufH, 0, BF_SIZE*BF_PER_FILE);
                    inH.close();

                    for(fileV=1; fileV<=BF_PER_FILE; fileV++) {
                        for(fileH=1; fileH<=BF_PER_FILE; fileH++) {
                            jaccard = jaccardCalc(bfBufV, (fileV-1)*BF_SIZE, bfBufH, (fileH-1)*BF_SIZE);
                            if (jaccard > 0.8) {
                                fileNumberV = (dataFileV*BF_PER_FILE) + fileV;
                                fileNumberH = (dataFileH*BF_PER_FILE) + fileH;
                                bitShredKey.set(formatter.format(jaccard));
                                bitShredValue.set(String.format(":%d:%d:", fileNumberV, fileNumberH));
                                output.collect(bitShredKey, bitShredValue);
                            }
                        }
                    }
                }
                else {
                    for(fileV=1; fileV<BF_PER_FILE; fileV++) {
                        for(fileH=fileV+1; fileH<=BF_PER_FILE; fileH++) {
                            jaccard = jaccardCalc(bfBufV, (fileV-1)*BF_SIZE, bfBufV, (fileH-1)*BF_SIZE);
                            if (jaccard > 0.8) {
                                fileNumberV = (dataFileV*BF_PER_FILE) + fileV;
                                fileNumberH = (dataFileH*BF_PER_FILE) + fileH;
                                bitShredKey.set(formatter.format(jaccard));
                                bitShredValue.set(String.format(":%d:%d:", fileNumberV, fileNumberH));
                                output.collect(bitShredKey, bitShredValue);
                            }
                        }
                    }
                }
            }
        }

        public static float jaccardCalc(byte[] bf1, int offset1, byte[] bf2, int offset2) {
            int tmp1 = 0;
            int tmp2 = 0;
            int numberSetUnion = 0;
            int numberSetIntersection = 0;
            float jaccard;
            int i = 0;

            for(i=0; i<BF_SIZE/4; i++) {
                tmp1 = (bf1[offset1+i*4+0]&0xFF) | (bf1[offset1+i*4+1]&0xFF)<<8 | (bf1[offset1+i*4+2]&0xFF)<<16 | (bf1[offset1+i*4+3]&0xFF)<<24;
                tmp2 = (bf2[offset2+i*4+0]&0xFF) | (bf2[offset2+i*4+1]&0xFF)<<8 | (bf2[offset2+i*4+2]&0xFF)<<16 | (bf2[offset2+i*4+3]&0xFF)<<24;
                numberSetIntersection += Integer.bitCount(tmp1&tmp2);
                numberSetUnion += Integer.bitCount(tmp1|tmp2);
            }
            // error handling
            if (numberSetUnion == 0) {
                return 0;
            }
            else {
                jaccard = numberSetIntersection / (float)numberSetUnion;
                return jaccard;
            }
        }
    }

//    public static class Reduce extends MapReduceBase implements Reducer<Text, IntWritable, Text, IntWritable> {
//      public void reduce(Text key, Iterator<IntWritable> values, OutputCollector<Text, IntWritable> output, Reporter reporter) throws IOException {
//        int sum = 0;
//        while (values.hasNext()) {
//          sum += values.next().get();
//        }
//        output.collect(key, new IntWritable(sum));
//      }
//    }

    public static void main(String[] args) throws Exception {
        JobConf conf = new JobConf(Cmp.class);
        conf.setJobName("bitshred_cmp");
        //int numData = 250;

//        for(int i=0; i<numData; i++) {
//            DistributedCache.addCacheFile(new URI("/user/jiyongj/bf/data"+Integer.toString(i)), conf);
//        }

        conf.setOutputKeyClass(Text.class);
        conf.setOutputValueClass(Text.class);
        conf.setInputFormat(TextInputFormat.class);
        conf.setOutputFormat(TextOutputFormat.class);

        conf.setMapperClass(Map.class);
        //conf.setCombinerClass(Reduce.class);
        //conf.setReducerClass(Reduce.class);

        FileInputFormat.setInputPaths(conf, new Path(args[0]));
        FileOutputFormat.setOutputPath(conf, new Path(args[1]));

        JobClient.runJob(conf);
    }
}
