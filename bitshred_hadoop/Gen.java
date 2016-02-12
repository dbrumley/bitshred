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

public class Gen {

    public static class Map extends MapReduceBase implements Mapper<LongWritable, Text, IntWritable, Text> {
        private final static String SAMPLE_PATH = "/user/jiyongj/unpacked/";  // path to malware samples
        private final static int SHRED_SIZE = 16;                             // size of a shred
        private final static int FP_SIZE = 1024*32;                           // size of a fingerprint (in bytes)
        private final static int WINDOW_SIZE = 12;                            // size of a window (Winnowing)
        private IntWritable bitShredKey = new IntWritable();
        private Text bitShredValue = new Text();

        private final static String DATA_PATH = "/user/jiyongj/fp-unpacked/data";    // path to fingerprints
        private final static String NBITS_PATH = "/user/jiyongj/fp-unpacked/nbits";  // path to set bits
        private final static int FP_PER_FILE = 2048;                          // number of fingerprints per file
        private byte[] outBuf = new byte[FP_SIZE*FP_PER_FILE];
        private int[] outNBits = new int[FP_PER_FILE];
        private String inputFile;

        public void configure(JobConf job) {
            String inputPath = job.get("map.input.file");
            StringTokenizer st = new StringTokenizer(inputPath, "/");
            while(st.hasMoreTokens()){
                inputFile = st.nextToken();
            }
        }

        public void map(LongWritable key, Text value, OutputCollector<IntWritable, Text> output, Reporter reporter) throws IOException {
            FileSystem fs = FileSystem.get(new Configuration());
            String line = value.toString();
            StringTokenizer st = new StringTokenizer(line);
            int sampleNumber = Integer.parseInt(st.nextToken());
            String sampleName = st.nextToken();
            Path samplePath = new Path(SAMPLE_PATH+sampleName);
            FSDataInputStream in = fs.open(samplePath);
            int numberSetBit;
            int k;

            byte[] buf = new byte[8];
            in.read(60, buf, 0, 4);
            long offsetOfPEHeader = (long)((buf[0]&0xFF) | (buf[1]&0xFF)<<8 | (buf[2]&0xFF)<<16 | (buf[3]&0xFF)<<24) & 0xFFFFFFFFL;
            in.read(offsetOfPEHeader, buf, 0, 8);

            // Check PE file Signature
            if(buf[0]==0x50 && buf[1]==0x45 && buf[2]==0x00 && buf[3]==0x00) {
                long offsetOfNumberOfSections = offsetOfPEHeader + 6;
                long offsetOfSizeOfOptHeader = offsetOfPEHeader + 20;
                long offsetOfEntryPoint = offsetOfPEHeader + 40;
                long offsetOfImageBase = offsetOfPEHeader + 52;

                in.read(offsetOfNumberOfSections, buf, 0, 2);
                long numberOfSections = (buf[0]&0xFF) | (buf[1]&0xFF)<<8;

                in.read(offsetOfEntryPoint, buf, 0, 4);
                long entryPoint = (long)((buf[0]&0xFF) | (buf[1]&0xFF)<<8 | (buf[2]&0xFF)<<16 | (buf[3]&0xFF)<<24) & 0xFFFFFFFFL;

                in.read(offsetOfImageBase, buf, 0, 4);
                long imageBase = (long)((buf[0]&0xFF) | (buf[1]&0xFF)<<8 | (buf[2]&0xFF)<<16 | (buf[3]&0xFF)<<24) & 0xFFFFFFFFL;

                in.read(offsetOfSizeOfOptHeader, buf, 0, 2);
                long sizeOfOptHeader = (buf[0]&0xFF) | (buf[1]&0xFF)<<8;
                long offsetOfSectionTable = offsetOfPEHeader + 24 + sizeOfOptHeader;

                for(int i=0; i<numberOfSections; i++) {
                    long offsetOfCurSection = offsetOfSectionTable + (40*i);

                    // CODE or .text Section
                    /*
                    in.read(offsetOfCurSection, buf, 0, 8);
                    if((buf[0]==0x43 && buf[1]==0x4f && buf[2]==0x44 && buf[3]==0x45) || (buf[0]==0x2e && buf[1]==0x74 && buf[2]==0x65 && buf[3]==0x78 && buf[4]==0x74)) {
                        in.read(offsetOfCurSection+8, buf, 0, 4);
                        long virtualSize = (long)((buf[0]&0xFF) | (buf[1]&0xFF)<<8 | (buf[2]&0xFF)<<16 | (buf[3]&0xFF)<<24) & 0xFFFFFFFFL;
                        in.read(offsetOfCurSection+16, buf, 0, 4);
                        long sizeOfRawData = (long)((buf[0]&0xFF) | (buf[1]&0xFF)<<8 | (buf[2]&0xFF)<<16 | (buf[3]&0xFF)<<24) & 0xFFFFFFFFL;
                        long sectionSize = (virtualSize < sizeOfRawData) ? virtualSize : sizeOfRawData;

                        in.read(offsetOfCurSection+20, buf, 0, 4);
                        long pointerToRawData = (long)((buf[0]&0xFF) | (buf[1]&0xFF)<<8 | (buf[2]&0xFF)<<16 | (buf[3]&0xFF)<<24) & 0xFFFFFFFFL;
                        byte[] sectionData = new byte[(int)sectionSize];
                        in.read(pointerToRawData, sectionData, 0, (int)sectionSize);

                        bitShred bs = new bitShred(sectionData, (int)sectionSize, SHRED_SIZE, FP_SIZE, WINDOW_SIZE);
                        bs.fingerPrinting();
                        
                        //Path bfPath = new Path(BF_PATH+sampleNumber);
                        //FSDataOutputStream out = fs.create(bfPath);
                        //out.write(bs.bloomFilter, 0, FP_SIZE);
                        //out.close();

                        bitShredKey.set(Integer.parseInt(sampleNumber));
                        bitShredValue.set(bs.bloomFilter, 0, FP_SIZE);
                        output.collect(bitShredKey, bitShredValue);
                    }
                    */

                    // Executable Section located at Entry Point
                    in.read(offsetOfCurSection+12, buf, 0, 4);
                    long virtualAddress = (long)((buf[0]&0xFF) | (buf[1]&0xFF)<<8 | (buf[2]&0xFF)<<16 | (buf[3]&0xFF)<<24) & 0xFFFFFFFFL;
                    in.read(offsetOfCurSection+8, buf, 0, 4);
                    long virtualSize = (long)((buf[0]&0xFF) | (buf[1]&0xFF)<<8 | (buf[2]&0xFF)<<16 | (buf[3]&0xFF)<<24) & 0xFFFFFFFFL;
                    in.read(offsetOfCurSection+16, buf, 0, 4);
                    long sizeOfRawData = (long)((buf[0]&0xFF) | (buf[1]&0xFF)<<8 | (buf[2]&0xFF)<<16 | (buf[3]&0xFF)<<24) & 0xFFFFFFFFL;
                    long sectionSize = (virtualSize < sizeOfRawData) ? virtualSize : sizeOfRawData;

                    if((entryPoint >= virtualAddress) && (entryPoint < virtualAddress+sectionSize)) {
                        // IMAGE_SCN_CNT_CODE || IMAGE_SCN_MEM_EXECUTE (Characteristics)
                        in.read(offsetOfCurSection+36, buf, 0, 4);
                        if((buf[0]&0x20)==0x20 || (buf[3]&0x20)==0x20) {
                            in.read(offsetOfCurSection+20, buf, 0, 4);
                            long pointerToRawData = (long)((buf[0]&0xFF) | (buf[1]&0xFF)<<8 | (buf[2]&0xFF)<<16 | (buf[3]&0xFF)<<24) & 0xFFFFFFFFL;
                            byte[] sectionData = new byte[(int)sectionSize];
                            in.read(pointerToRawData, sectionData, 0, (int)sectionSize);

                            bitShred bs = new bitShred(sectionData, (int)sectionSize, SHRED_SIZE, FP_SIZE, WINDOW_SIZE);
                            bs.fingerPrinting();

                            for(k=0; k<FP_SIZE; k++) {
                                outBuf[((sampleNumber-1)%FP_PER_FILE)*FP_SIZE+k] = bs.fingerPrint[k];
                            }
                            numberSetBit = 0;
                            for(k=0; k<FP_SIZE/4; k++) {
                                numberSetBit += Integer.bitCount( (bs.fingerPrint[k*4]&0xFF) | (bs.fingerPrint[k*4+1]&0xFF)<<8 | (bs.fingerPrint[k*4+2]&0xFF)<<16 | (bs.fingerPrint[k*4+3]&0xFF)<<24 );
                            }
                            outNBits[(sampleNumber-1)%FP_PER_FILE] = numberSetBit;
                            bitShredKey.set(sampleNumber);
                            bitShredValue.set(Integer.toString(numberSetBit));
                            output.collect(bitShredKey, bitShredValue);
                        }
                        break;
                    }
                }
            }
            in.close();
            if(sampleNumber%FP_PER_FILE == 0) {
                Path dataPath = new Path(DATA_PATH+inputFile);
                Path nBitsPath = new Path(NBITS_PATH+inputFile);
                FSDataOutputStream out = fs.create(dataPath);
                out.write(outBuf, 0, FP_SIZE*FP_PER_FILE);
                out.close();
                out = fs.create(nBitsPath);
                for(k=0; k<FP_PER_FILE; k++) {
                    out.writeInt(outNBits[k]);
                }
                out.close();
            }
        }

    }

    public static class bitShred {
        public byte[] fingerPrint;
        public static int fingerPrintSize;
        public byte[] sectionData;
        public static int sectionSize;
        public static int shredSize;        // size of a shred
        public static int windowSize;       // size of a window (Winnowing)

        public bitShred(byte[] sectionData, int sectionSize , int shredSize, int fingerPrintSize, int windowSize) {
            this.sectionData = new byte[sectionSize];
            for(int i=0; i<sectionSize; i++) {
                this.sectionData[i] = sectionData[i];    
            }
            this.sectionSize = sectionSize;
            this.shredSize = shredSize;
            this.fingerPrintSize = fingerPrintSize;
            this.fingerPrint = new byte[fingerPrintSize];
            this.windowSize = windowSize;
        }

        public void fingerPrinting() {
            int numberOfShreds = sectionSize - (shredSize-1);
            /* Previous BitShred */
            /*
            long hash1;
            long hash2;
            long hash3;
            
            for(int i=0; i<numberOfShreds; i++) {
                hash1 = djb2(i) & (long)(bloomFilterSize*8-1);
                hash2 = sdbm(i) & (long)(bloomFilterSize*8-1);
                hash3 = jenkins(i) & (bloomFilterSize*8-1);
 
                bloomFilterSet(hash1);
                bloomFilterSet(hash2);
                bloomFilterSet(hash3);
            }
            */

            /* Current BitShred */
            int minId = -1;
            long minHash = 0;
            long tmpHash = 0;
            for(int i=0; i<(numberOfShreds-windowSize+1); i++) {
                if(minId < i) {
                    minHash = djb2(i);
                    minId = i;
                    for(int j=1; j<windowSize; j++) {
                        tmpHash = djb2(i+j);
                        if(tmpHash <= minHash) {
                            minHash = tmpHash;
                            minId = i+j;
                        }
                    }
                    bitVectorSet(minHash & (long)(fingerPrintSize*8-1));
                }
                else {
                    tmpHash = djb2(i+windowSize-1);
                    if(tmpHash <= minHash) {
                        minHash = tmpHash;
                        minId = i+windowSize-1;
                        bitVectorSet(minHash & (long)(fingerPrintSize*8-1));
                    }
                }
            }
        }

        private void bitVectorSet(long offset) {
            int byteIndex = (int)(offset >>> 3);
            byte bitMask = (byte)(1 << ((int)offset & 0x07));
            fingerPrint[byteIndex] |= bitMask;
        }

        /* Hash functions */
        private long djb2(int index) {
            long hash = 5381;
            int c;
            int i;
            for(i=0; i<shredSize; i++) {
                c = sectionData[index+i] & 0xFF;
                hash = (((hash << 5) + hash) + (long)c) & 0xFFFFFFFFL;   // hash * 33 + ptr[i]
            }
            return hash;
        }
        
        private long sdbm(int index) {
            long hash = 0;
            int c;
            int i;
            for(i=0; i<shredSize; i++) {
                c = sectionData[index+i] & 0xFF;
                hash = ((long)c + (hash << 6) + (hash << 16 ) - hash) & 0xFFFFFFFFL;
            }
            return hash;
        }

        private long jenkins(int index) {
            long hash = 0;
            int c;
            int i;
            for(i=0; i<shredSize; i++) {
                c = sectionData[index+i] & 0xFF;
                hash += c;
                hash += (hash << 10);
                hash ^= (hash >>> 6);
                hash = hash & 0xFFFFFFFFL;
            }
            hash += (hash << 3);
            hash ^= (hash >>> 11);
            hash += (hash << 15);
            hash = hash & 0xFFFFFFFFL;
            return hash;
        }
    }

    public static void main(String[] args) throws Exception {
        JobConf conf = new JobConf(Gen.class);
        conf.setJobName("bitshred_gen");

        conf.setOutputKeyClass(IntWritable.class);
        conf.setOutputValueClass(Text.class);
        conf.setInputFormat(TextInputFormat.class);
        conf.setOutputFormat(TextOutputFormat.class);

        conf.setMapperClass(Map.class);

        FileInputFormat.setInputPaths(conf, new Path(args[0]));
        FileOutputFormat.setOutputPath(conf, new Path(args[1]));

        JobClient.runJob(conf);
    }
}

