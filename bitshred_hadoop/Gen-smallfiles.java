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

public class Gen {

    public static class Map extends MapReduceBase implements Mapper<LongWritable, Text, IntWritable, Text> {
        private final static String SAMPLE_PATH = "/user/jiyongj/sample/";
        private final static String BF_PATH = "/user/jiyongj/bf/tmp/";
        private final static int SHRED_SIZE = 16;
        private final static int BF_SIZE = 1024*32;
        //private final static Path PATH = new Path("/user/jiyongj/bf/data");
        private IntWritable bitShredKey = new IntWritable();
        //private Text bitShredKey = new Text();
        private Text bitShredValue = new Text();

      //private final static IntWritable one = new IntWritable(1);
      //private Text word = new Text();

        //public void configure(JobConf job) {
        //    bfFile = job.get("map.input.file");
        //}

        public void map(LongWritable key, Text value, OutputCollector<IntWritable, Text> output, Reporter reporter) throws IOException {
            FileSystem fs = FileSystem.get(new Configuration());
            String line = value.toString();
            StringTokenizer st = new StringTokenizer(line, ":");
            String sampleNumber = st.nextToken();
            String sampleName = st.nextToken();
            Path samplePath = new Path(SAMPLE_PATH+sampleName);
            FSDataInputStream in = fs.open(samplePath);

            byte[] buf = new byte[8];
            in.read(60, buf, 0, 4);
            long offsetOfPEHeader = (buf[0]&0xff) | (buf[1]&0xff)<<8 | (buf[2]&0xff)<<16 | (buf[3]&0xff)<<24;
            in.read(offsetOfPEHeader, buf, 0, 8);

            // Check PE file Signature
            if(buf[0]==0x50 && buf[1]==0x45 && buf[2]==0x00 && buf[3]==0x00) {
                long offsetOfNumberOfSections = offsetOfPEHeader + 6;
                long offsetOfSizeOfOptHeader = offsetOfPEHeader + 20;
                long offsetOfEntryPoint = offsetOfPEHeader + 40;
                long offsetOfImageBase = offsetOfPEHeader + 52;

                in.read(offsetOfNumberOfSections, buf, 0, 2);
                long numberOfSections = (buf[0]&0xff) | (buf[1]&0xff)<<8;

                in.read(offsetOfEntryPoint, buf, 0, 4);
                long entryPoint = (buf[0]&0xff) | (buf[1]&0xff)<<8 | (buf[2]&0xff)<<16 | (buf[3]&0xff)<<24;

                in.read(offsetOfImageBase, buf, 0, 4);
                long imageBase = (buf[0]&0xff) | (buf[1]&0xff)<<8 | (buf[2]&0xff)<<16 | (buf[3]&0xff)<<24;

                in.read(offsetOfSizeOfOptHeader, buf, 0, 2);
                long sizeOfOptHeader = (buf[0]&0xff) | (buf[1]&0xff)<<8;
                long offsetOfSectionTable = offsetOfPEHeader + 24 + sizeOfOptHeader;

                for(int i=0; i<numberOfSections; i++) {
                    long offsetOfCurSection = offsetOfSectionTable + (40*i);

                    // CODE or .text Section
                    in.read(offsetOfCurSection, buf, 0, 8);
                    if((buf[0]==0x43 && buf[1]==0x4f && buf[2]==0x44 && buf[3]==0x45) || (buf[0]==0x2e && buf[1]==0x74 && buf[2]==0x65 && buf[3]==0x78 && buf[4]==0x74)) {
                        in.read(offsetOfCurSection+8, buf, 0, 4);
                        long virtualSize = (buf[0]&0xff) | (buf[1]&0xff)<<8 | (buf[2]&0xff)<<16 | (buf[3]&0xff)<<24;
                        in.read(offsetOfCurSection+20, buf, 0, 4);
                        long pointerToRawData = (buf[0]&0xff) | (buf[1]&0xff)<<8 | (buf[2]&0xff)<<16 | (buf[3]&0xff)<<24;
                        byte[] sectionData = new byte[(int)virtualSize];
                        in.read(pointerToRawData, sectionData, 0, (int)virtualSize);

                        bitShred bs = new bitShred(sectionData, (int)virtualSize, SHRED_SIZE, BF_SIZE);
                        bs.fingerPrinting();
                        
                        Path bfPath = new Path(BF_PATH+sampleNumber);
                        FSDataOutputStream out = fs.create(bfPath);
                        out.write(bs.bloomFilter, 0, BF_SIZE);
                        out.close();

                        bitShredKey.set(Integer.parseInt(sampleNumber));
                        bitShredValue.set(sampleName);
                        output.collect(bitShredKey, bitShredValue);

                        break;
                    }

                    /*
                    // Executable Section located at Entry Point
                    in.read(offsetOfCurSection+12, buf, 0, 4);
                    long virtualAddress = (buf[0]&0xff) | (buf[1]&0xff)<<8 | (buf[2]&0xff)<<16 | (buf[3]&0xff)<<24;
                    in.read(offsetOfCurSection+8, buf, 0, 4);
                    long virtualSize = (buf[0]&0xff) | (buf[1]&0xff)<<8 | (buf[2]&0xff)<<16 | (buf[3]&0xff)<<24;
                    if((entryPoint+imageBase >= virtualAddress) && (entryPoint+imageBase < virtualAddress+virtualSize)) {
                        // Executabl Code (Characteristics)
                        in.read(offsetOfCurSection+36, buf, 0, 4);
                        if((buf[0]&0x20)==0x20 && (buf[3]&0x20)==0x20) {
                            in.read(offsetOfCurSection+20, buf, 0, 4);
                            long pointerToRawData = (buf[0]&0xff) | (buf[1]&0xff)<<8 | (buf[2]&0xff)<<16 | (buf[3]&0xff)<<24;
                            byte[] sectionData = new byte[virtualSize];
                            in.read(pointerToRawData, sectionData, 0, virtualSize);
                        }
                    }
                    */
                }
            }
            in.close();
        }

    }

    public static class Reduce extends MapReduceBase implements Reducer<IntWritable, Text, IntWritable, Text> {
        private final static String BF_PATH = "/user/jiyongj/bf/tmp/";
        private final static String DATA_PATH = "/user/jiyongj/bf/data";
        private final static int BF_SIZE = 1024*32;
        //private final static int BF_PER_FILE = 10240;
        private final static int BF_PER_FILE = 9216;
        private byte[] outBuf = new byte[BF_SIZE*BF_PER_FILE];
        private int fileCounter = 0;

        public void reduce(IntWritable key, Iterator<Text> values, OutputCollector<IntWritable, Text> output, Reporter reporter) throws IOException {
            int sampleNumber = key.get();
            FileSystem fs = FileSystem.get(new Configuration());
            Path bfPath = new Path(BF_PATH+Integer.toString(sampleNumber));
            FSDataInputStream in = fs.open(bfPath);
            //if (fs.exists(dataPath)) {
            //    FSDataOutputStream out = fs.append(dataPath);
            //}
            //else {
            //    FSDataOutputStream out = fs.create(dataPath);
            //}

            in.read(0, outBuf, (sampleNumber-1)*BF_SIZE, BF_SIZE);
            in.close();

            if(sampleNumber!=1 && sampleNumber%BF_PER_FILE==0) {
                Path dataPath = new Path(DATA_PATH+Integer.toString(fileCounter));
                FSDataOutputStream out = fs.create(dataPath);
                out.write(outBuf, 0, BF_SIZE*BF_PER_FILE);
                out.close();
                fileCounter++;
            }
            output.collect(key, values.next());
        }
    }

    public static class bitShred {
        public byte[] bloomFilter;
        public static int bloomFilterSize;
        public byte[] sectionData;
        public static int sectionSize;
        public static int shredSize;

        public bitShred(byte[] sectionData, int virtualSize, int shredSize, int bloomFilterSize) {
            this.sectionData = new byte[virtualSize];
            for(int i=0; i<virtualSize; i++) {
                this.sectionData[i] = sectionData[i];    
            }
            this.sectionSize = virtualSize;
            this.shredSize = shredSize;
            this.bloomFilterSize = bloomFilterSize;
            this.bloomFilter = new byte[bloomFilterSize];
        }

        public void fingerPrinting() {
            int numberOfShreds = sectionSize - (shredSize-1);
            int hash1, hash2;
            //int hash3;
            for(int i=0; i<numberOfShreds; i++) {
                hash1 = djb2(i) & (bloomFilterSize*8-1);
                hash2 = sdbm(i) & (bloomFilterSize*8-1);
                //hash3 = jenkins(i) & (bloomFilterSize*8-1);

                bloomFilterSet(hash1);
                bloomFilterSet(hash2);
                //bloomFilterSet(hash3);
            }
        }

        private void bloomFilterSet(int offset) {
            int byteIndex = offset >>> 3;
            byte bitMask = (byte)(1 << (offset & 0x00000007));
            bloomFilter[byteIndex] |= bitMask;
        }

        private int djb2(int index) {
            long hash = 5381;
            int c;
            int i;
            for(i=0; i<shredSize; i++) {
                c = sectionData[index+i] & 0xff;
                hash = (((hash << 5) + hash) + c) & 0xffffffff;   // hash * 33 + ptr[i]
            }
            return (int)hash;
        }
        
        private int sdbm(int index) {
            long hash = 0;
            int c;
            int i;
            for(i=0; i<shredSize; i++) {
                c = sectionData[index+i] & 0xff;
                hash = (c + (hash << 6) + (hash << 16 ) - hash) & 0xffffffff;
            }
            return (int)hash;
        }

        private int jenkins(int index) {
            long hash = 0;
            int c;
            int i;
            for(i=0; i<shredSize; i++) {
                c = sectionData[index+i] & 0xff;
                hash += c;
                hash += (hash << 10);
                hash ^= (hash >>> 6);
                hash = hash & 0xffffffff;
            }
            hash += (hash << 3);
            hash ^= (hash >>> 11);
            hash += (hash << 15);
            hash = hash & 0xffffffff;
            return (int)hash;
        }
    }

    public static void main(String[] args) throws Exception {
        JobConf conf = new JobConf(Gen.class);
        conf.setJobName("bitshred_gen");

        //DistributedCache.addCacheFile(new URI("/user/jiyongj/bf/data"), conf);

        conf.setOutputKeyClass(IntWritable.class);
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

