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
        //private final static String PATH = "/user/jiyongj/bf/data";
        //private final static Path PATH = new Path("/user/jiyongj/bf/data");
        private Text bitShredKey = new Text();
        private Text bitShredValue = new Text();

      //private final static IntWritable one = new IntWritable(1);
      //private Text word = new Text();
        private FileSystem fs;
        private Path[] localFiles;
        private int numBF = 9216;

        public void configure(JobConf job) {
            try {
                fs = FileSystem.getLocal(new Configuration());
                localFiles = DistributedCache.getLocalCacheFiles(job);
            } catch (IOException ioe) {
                System.err.println("Caught exception while getting cached files");
            }
        }

        public void map(LongWritable key, Text value, OutputCollector<Text, Text> output, Reporter reporter) throws IOException {
            //Configuration conf = new Configuration();
            //FileSystem fs = FileSystem.get(conf);
            //FSDataInputStream in = fs.open(PATH);
            byte[] bf1 = new byte[BF_SIZE];
            byte[] bf2 = new byte[BF_SIZE];
            //int[] bf1 = new int[BF_SIZE/4];
            //int[] bf2 = new int[BF_SIZE/4];
            float jaccard;
            NumberFormat formatter = new DecimalFormat("#.######");

            String file1 = value.toString();
            Path filePath1 = new Path(localFiles[0].toString()+file1);
            //FSDataInputStream in = fs.open(filePath1);
            FSDataInputStream in = fs.open(localFiles[0]);
            in.read(0, bf1, 0, BF_SIZE);
            in.close();
            int fileNumber1 = Integer.parseInt(file1);
            int fileNumber2;
            for (fileNumber2=fileNumber1+1; fileNumber2<=numBF; fileNumber2++) {
                Path filePath2 = new Path(localFiles[0].toString()+Integer.toString(fileNumber2));
                in = fs.open(filePath2);
                in.read(0, bf2, 0, BF_SIZE);

//            StringTokenizer st = new StringTokenizer(line, ":");
//            String file1 = st.nextToken();
//            String file2 = st.nextToken();
//            int offset1 = (Integer.parseInt(file1)-1)*BF_SIZE;
//            int offset2 = (Integer.parseInt(file2)-1)*BF_SIZE;
            

            //Path path1 = new Path(PATH+file1);
            //FSDataInputStream in1 = fs.open(path1);
            //for(i=0; i<BF_SIZE/4; i++) {
            //    bf1[i] = in1.readInt();
            //}
            //in1.read(0, bf1, 0, BF_SIZE);
            //in1.close();
  
            //Path path2 = new Path(PATH+file2);
            //FSDataInputStream in2 = fs.open(path2);
            //for(i=0; i<BF_SIZE/4; i++) {
            //    bf2[i] = in2.readInt();
            //}
            //in2.read(0, bf2, 0, BF_SIZE);
            //in2.close();

            jaccard = jaccardCalc(bf1, bf2);

            //if (jaccard > 0.5) {
                bitShredKey.set(formatter.format(jaccard));
                bitShredValue.set(String.format(":%d:%d:", fileNumber1, fileNumber2));

                output.collect(bitShredKey, bitShredValue);
            //}


            }
            in.close();
        }

        public static float jaccardCalc(byte[] bf1, byte[] bf2) {
            int tmp1 = 0;
            int tmp2 = 0;
            int numberSetUnion = 0;
            int numberSetIntersection = 0;
            float jaccard;
            int i = 0;

            for(i=0; i<BF_SIZE/4; i++) {
                tmp1 = (bf1[i*4+0]&0xff)<<24 | (bf1[i*4+1]&0xff)<<16 | (bf1[i*4+2]&0xff)<<8 | (bf1[i*4+3]&0xff);
                tmp2 = (bf2[i*4+0]&0xff)<<24 | (bf2[i*4+1]&0xff)<<16 | (bf2[i*4+2]&0xff)<<8 | (bf2[i*4+3]&0xff);
                numberSetIntersection += Integer.bitCount(tmp1&tmp2);
                numberSetUnion += Integer.bitCount(tmp1|tmp2);
                //numberSetIntersection += Integer.bitCount(bf1[i]&bf2[i]);
                //numberSetUnion += Integer.bitCount(bf1[i]|bf1[i]);
            }
            jaccard = numberSetIntersection / (float)numberSetUnion;
            return jaccard;
            //return Math.round(jaccard*1000000.0)/(float)1000000.0;
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
        conf.setJobName("bitshred");

        DistributedCache.addCacheFile(new URI("/user/jiyongj/bf/"), conf);

        conf.setOutputKeyClass(Text.class);
        conf.setOutputValueClass(Text.class);
        conf.setInputFormat(TextInputFormat.class);
        conf.setOutputFormat(TextOutputFormat.class);

        conf.setMapperClass(Map.class);
        //conf.setCombinerClass(Reduce.class);
        //conf.setReducerClass(Reduce.class);

        //numBF = Integer.parseInt(args[0]);
        FileInputFormat.setInputPaths(conf, new Path(args[0]));
        FileOutputFormat.setOutputPath(conf, new Path(args[1]));

        JobClient.runJob(conf);
    }
}

