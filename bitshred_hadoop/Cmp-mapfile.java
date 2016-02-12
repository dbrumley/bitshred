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
        //private final static int BF_PER_FILE = 10240;
        //private int numBF = 501760;
        private int numBF = 10080;
        //private Text bitShredKey = new Text();
        //private Text bitShredValue = new Text();

        private FileSystem fs;
        private MapFile.Reader reader;
        private final static String DATA_PATH = "/user/jiyongj/bf/data";
//        private Path[] localFiles;
        private IntWritable bitShredKey;
        private BytesWritable bitShredValue;
        private Text bitShredKey2 = new Text();
        private Text bitShredValue2 = new Text();

        public void configure(JobConf job) {
            try {
                Configuration conf = new Configuration();
                fs = FileSystem.get(conf);
                reader = new MapFile.Reader(fs, DATA_PATH, conf);
//                fs = FileSystem.getLocal(conf);
//                localFiles = DistributedCache.getLocalCacheFiles(job);
            } catch (IOException ioe) {
                System.err.println("Caught exception while getting cached files");
            } 
        }

        public void map(LongWritable key, Text value, OutputCollector<Text, Text> output, Reporter reporter) throws IOException {
            byte[] bf1 = new byte[BF_SIZE];
            byte[] bf2 = new byte[BF_SIZE];
            float jaccard;
            NumberFormat formatter = new DecimalFormat("#.######");
            int file2;

            //FSDataInputStream[] in = new FSDataInputStream[numBF/BF_PER_FILE];
            //FSDataInputStream[] in = new FSDataInputStream[10];
            //for(int i=0; i<10; i++) {
            //    in[i] = fs.open(localFiles[i]);
            //}

            bitShredKey = null;
            bitShredValue = null;

            try {
                bitShredKey = (IntWritable) reader.getKeyClass().newInstance();
                bitShredValue = (BytesWritable) reader.getValueClass().newInstance();
            } catch (InstantiationException ite) {
            } catch (IllegalAccessException iae) {
            }

            String line = value.toString();
            int file1 = Integer.parseInt(line);
            bitShredKey.set(file1);
            bitShredValue = (BytesWritable) reader.get(bitShredKey, bitShredValue);
            if (bitShredValue == null) {
                bitShredKey2.set(line);
                bitShredValue2.set("bf1");
                output.collect(bitShredKey2, bitShredValue2);
            }
            else {
                bf1 = bitShredValue.getBytes();
            }

            //int offset1 = ((file1-1)%BF_PER_FILE)*BF_SIZE;
            //int dataNumber1 = (int)((file1-1)/BF_PER_FILE);
            //in[dataNumber1].read(offset1, bf1, 0, BF_SIZE);
            for (file2=file1+1; file2<=numBF; file2++) {
                bitShredKey = null;
                bitShredValue = null;
                try {
                    bitShredKey = (IntWritable) reader.getKeyClass().newInstance();
                    bitShredValue = (BytesWritable) reader.getValueClass().newInstance();
                } catch (InstantiationException ite) {
                } catch (IllegalAccessException iae) {
                }
                bitShredKey.set(file2);
                bitShredValue = (BytesWritable) reader.get(bitShredKey, bitShredValue);
                if (bitShredValue == null) {
                    bitShredKey2.set(Integer.toString(file2));
                    bitShredValue2.set("bf2");
                    output.collect(bitShredKey2, bitShredValue2);
                }
                else {
                    bf2 = bitShredValue.getBytes();
                }

                jaccard = jaccardCalc(bf1, bf2);
                if (jaccard > 0.8) {
                    bitShredKey2.set(formatter.format(jaccard));
                    bitShredValue2.set(String.format(":%d:%d:", file1, file2));
                    output.collect(bitShredKey2, bitShredValue2);
                }
            }
//            for(int i=0; i<numBF/BF_PER_FILE; i++) {
//                in[i].close();
//            }
        }

        public void close() throws IOException {
            reader.close();
        }

        public static float jaccardCalc(byte[] bf1, byte[] bf2) {
            int tmp1 = 0;
            int tmp2 = 0;
            int numberSetUnion = 0;
            int numberSetIntersection = 0;
            float jaccard;
            int i = 0;

            for(i=0; i<BF_SIZE/4; i++) {
                tmp1 = (bf1[i*4+0]&0xFF) | (bf1[i*4+1]&0xFF)<<8 | (bf1[i*4+2]&0xFF)<<16 | (bf1[i*4+3]&0xFF)<<24;
                tmp2 = (bf2[i*4+0]&0xFF) | (bf2[i*4+1]&0xFF)<<8 | (bf2[i*4+2]&0xFF)<<16 | (bf2[i*4+3]&0xFF)<<24;
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
        //int BF_PER_FILE = 10240;
        //int numBF = 501760;
        //int numBF = 102400;

        //for(int i=0; i<10; i++) {
        //    DistributedCache.addCacheFile(new URI("/user/jiyongj/bf/data"+Integer.toString(i)), conf);
        //}

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
