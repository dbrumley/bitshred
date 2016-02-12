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
        private final static int BF_PER_FILE = 10240;
        //private int numBF = 501760;
        private int numBF = 102240;
        private int numData = 10;
        private Text bitShredKey = new Text();
        private Text bitShredValue = new Text();

        private FileSystem fs;
        private Path[] localFiles;
        //FSDataInputStream[] in = new FSDataInputStream[numBF/BF_PER_FILE];

        public void configure(JobConf job) {
            try {
                fs = FileSystem.getLocal(new Configuration());
                localFiles = DistributedCache.getLocalCacheFiles(job);
            } catch (IOException ioe) {
                System.err.println("Caught exception while getting cached files");
            }
        }

        public void map(LongWritable key, Text value, OutputCollector<Text, Text> output, Reporter reporter) throws IOException {
            byte[] bf1 = new byte[BF_SIZE];
            //byte[] bf2 = new byte[BF_SIZE];
            float jaccard;
            NumberFormat formatter = new DecimalFormat("#.######");
            int i;
            int file1, dataNumber1, offset1;
            int file2, dataNumber2, offset2;
            FSDataInputStream in;
            byte[] bfBuf = new byte[BF_SIZE*BF_PER_FILE];

            String line = value.toString();
            file1 = Integer.parseInt(line);
            dataNumber1 = (int)((file1-1)/BF_PER_FILE);
            in = fs.open(localFiles[dataNumber1]);
            //for(i=dataNumber1; i<numData; i++) {
            //    in[i] = fs.open(localFiles[i]);
            //}
            offset1 = ((file1-1)%BF_PER_FILE)*BF_SIZE;
            in.read(offset1, bf1, 0, BF_SIZE);
            in.close();

            int curDataNumber2 = -1;
            for (file2=file1+1; file2<=numBF; file2++) {
                dataNumber2 = (int)((file2-1)/BF_PER_FILE);
                if(dataNumber2 != curDataNumber2) {
                    curDataNumber2 = dataNumber2;
                    in = fs.open(localFiles[curDataNumber2]);
                    in.read(0, bfBuf, 0, BF_SIZE*BF_PER_FILE);
                    in.close();
                }
                offset2 = ((file2-1)%BF_PER_FILE)*BF_SIZE;
                //for(i=0; i<BF_SIZE; i++) {
                //    bf2[i] = bfBuf[offset2+i];
                //}
                //in[dataNumber2].read(offset2, bf2, 0, BF_SIZE);

                //jaccard = jaccardCalc(bf1, bf2);
                jaccard = jaccardCalc(bf1, bfBuf, offset2);
                if (jaccard > 0.8) {
                    bitShredKey.set(formatter.format(jaccard));
                    bitShredValue.set(String.format(":%d:%d:", file1, file2));
                    output.collect(bitShredKey, bitShredValue);
                }
            }
        }

        public static float jaccardCalc(byte[] bf1, byte[] bf2, int offset2) {
            int tmp1 = 0;
            int tmp2 = 0;
            int numberSetUnion = 0;
            int numberSetIntersection = 0;
            float jaccard;
            int i = 0;

            for(i=0; i<BF_SIZE/4; i++) {
                tmp1 = (bf1[i*4+0]&0xFF) | (bf1[i*4+1]&0xFF)<<8 | (bf1[i*4+2]&0xFF)<<16 | (bf1[i*4+3]&0xFF)<<24;
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
        int numData = 10;
        //int BF_PER_FILE = 10240;
        //int numBF = 501760;
        //int numBF = 102400;

        for(int i=0; i<numData; i++) {
            DistributedCache.addCacheFile(new URI("/user/jiyongj/bf/data"+Integer.toString(i)), conf);
        }

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
