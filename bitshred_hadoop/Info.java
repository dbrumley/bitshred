import java.io.IOException;
import java.util.*;
import java.net.URI;
import java.text.DecimalFormat;
import java.text.NumberFormat;

import org.apache.hadoop.filecache.DistributedCache;
import org.apache.hadoop.fs.*;
import org.apache.hadoop.conf.*;
import org.apache.hadoop.io.*;
import org.apache.hadoop.mapred.*;
import org.apache.hadoop.util.*;

public class Info {

    public static class Map extends MapReduceBase implements Mapper<LongWritable, Text, LongWritable, Text> {
        long blockSize;

        public void map(LongWritable key, Text value, OutputCollector<LongWritable, Text> output, Reporter reporter) throws IOException {

            FileSystem fs = FileSystem.get(new Configuration());
            blockSize = fs.getDefaultBlockSize();
            output.collect(new LongWritable(blockSize), new Text("a"));
        }
    }
/*
    public static class Reduce extends MapReduceBase implements Reducer<IntWritable, BytesWritable, IntWritable, NullWritable> {
        private final static String DATA_PATH = "/user/jiyongj/bf/data";
        private final static int BF_SIZE = 1024*32;
        private final static int BF_PER_FILE = 2048;
        byte[] bloomFilter = new byte[BF_SIZE];
        private byte[] outBuf = new byte[BF_SIZE*BF_PER_FILE];
        private int fileCounter = 0;

        public void reduce(IntWritable key, Iterator<BytesWritable> values, OutputCollector<IntWritable, NullWritable> output, Reporter reporter) throws IOException {
            FileSystem fs = FileSystem.get(new Configuration());
            int sampleNumber = key.get();
            bloomFilter = (values.next()).getBytes();
            for(int i=0; i<BF_SIZE; i++) {
                outBuf[((sampleNumber-1)%BF_PER_FILE)*BF_SIZE+i] = bloomFilter[i];
            }

            if(sampleNumber!=1 && sampleNumber%BF_PER_FILE==0) {
                Path dataPath = new Path(DATA_PATH+Integer.toString(fileCounter));
                FSDataOutputStream out = fs.create(dataPath);
                out.write(outBuf, 0, BF_SIZE*BF_PER_FILE);
                out.close();
                fileCounter++;
            }
            output.collect(key, null);
        }
    }
*/
    public static void main(String[] args) throws Exception {
        JobConf conf = new JobConf(Info.class);
        conf.setJobName("info");

        conf.setOutputKeyClass(LongWritable.class);
        conf.setOutputValueClass(Text.class);
        conf.setInputFormat(TextInputFormat.class);
        conf.setOutputFormat(TextOutputFormat.class);

        conf.setMapperClass(Map.class);
        //conf.setCombinerClass(Reduce.class);
        //conf.setReducerClass(Reduce.class);
        //conf.setNumReduceTasks(49);

        FileInputFormat.setInputPaths(conf, new Path(args[0]));
        FileOutputFormat.setOutputPath(conf, new Path(args[1]));

        JobClient.runJob(conf);
    }
}

