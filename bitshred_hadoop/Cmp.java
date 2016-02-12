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

    public static class Map extends MapReduceBase implements Mapper<LongWritable, Text, FloatWritable, Text> {
        private final static int FP_SIZE = 1024*32;         // size of a fingerprint (in bytes)
        private final static int FP_SIZE_INT = FP_SIZE/4;   // size of a fingerprint (in 4-bytes)
        private final static int FP_PER_FILE = 2048;        // number of fingerprints per file
        private final static float THRESHOLD = 0.5f;        // similarity threshold
        private final static int BLOCK_SIZE = 2*1024*1024;
        private int FP_PER_BLOCK = BLOCK_SIZE/FP_SIZE;
        private int BLOCK_PER_FILE = FP_PER_FILE/FP_PER_BLOCK;
        private FloatWritable bitShredKey = new FloatWritable();
        private Text bitShredValue = new Text();
        private final static String DATA_PATH = "/user/jiyongj/fp-unpacked/data";    // path to fingerprints
        private final static String NBITS_PATH = "/user/jiyongj/fp-unpacked/nbits";  // path to set bits

        private FileSystem fs;

        private FSDataInputStream inV;
        private FSDataInputStream inH;
        private byte[] bfBuf = new byte[FP_SIZE*FP_PER_FILE];
        private int[] bfBufV = new int[FP_SIZE_INT*FP_PER_FILE];
        private int[] bfBufH = new int[FP_SIZE_INT*FP_PER_FILE];
        private int curDataFileV = -1;
        private byte[] sizeBuf = new byte[FP_PER_FILE*4];
        private int[] codeSizeV = new int[FP_PER_FILE];
        private int[] codeSizeH = new int[FP_PER_FILE];

        public void configure(JobConf job) {
        }

        public void map(LongWritable key, Text value, OutputCollector<FloatWritable, Text> output, Reporter reporter) throws IOException {
            fs = FileSystem.get(new Configuration());
            //NumberFormat formatter = new DecimalFormat("#.######");
            float jaccard;

            String line = value.toString();
            StringTokenizer st = new StringTokenizer(line);
            int dataFileV = Integer.parseInt(st.nextToken());
            int dataFileH = Integer.parseInt(st.nextToken());
            int blockV, blockH;
            int blockOffsetV, blockOffsetH;
            int fileV, fileH;
            int fileNumberV, fileNumberH;
            int i;

            if (dataFileV != curDataFileV) {
                inV = fs.open(new Path(DATA_PATH+Integer.toString(dataFileV)));
                inV.read(0, bfBuf, 0, FP_SIZE*FP_PER_FILE);
                inV.close();
                for(i=0; i<FP_SIZE_INT*FP_PER_FILE; i++) {
                    bfBufV[i] = ((bfBuf[i*4]&0xFF)<<24) | ((bfBuf[i*4+1]&0xFF)<<16) | ((bfBuf[i*4+2]&0xFF)<<8) | (bfBuf[i*4+3]&0xFF);
                }
                inV = fs.open(new Path(NBITS_PATH+Integer.toString(dataFileV)));
                inV.read(0, sizeBuf, 0, FP_PER_FILE*4);
                inV.close();
                for(i=0; i<FP_PER_FILE; i++) {
                    codeSizeV[i] = ((sizeBuf[i*4]&0xFF)<<24) | ((sizeBuf[i*4+1]&0xFF)<<16) | ((sizeBuf[i*4+2]&0xFF)<<8) | (sizeBuf[i*4+3]&0xFF);
                }
                curDataFileV = dataFileV;
            }

            if (dataFileV != dataFileH) {
                inH = fs.open(new Path(DATA_PATH+Integer.toString(dataFileH)));
                inH.read(0, bfBuf, 0, FP_SIZE*FP_PER_FILE);
                inH.close();
                for(i=0; i<FP_SIZE_INT*FP_PER_FILE; i++) {
                    bfBufH[i] = ((bfBuf[i*4]&0xFF)<<24) | ((bfBuf[i*4+1]&0xFF)<<16) | ((bfBuf[i*4+2]&0xFF)<<8) | (bfBuf[i*4+3]&0xFF);
                }
                inH = fs.open(new Path(NBITS_PATH+Integer.toString(dataFileH)));
                inH.read(0, sizeBuf, 0, FP_PER_FILE*4);
                inH.close();
                for(i=0; i<FP_PER_FILE; i++) {
                    codeSizeH[i] = ((sizeBuf[i*4]&0xFF)<<24) | ((sizeBuf[i*4+1]&0xFF)<<16) | ((sizeBuf[i*4+2]&0xFF)<<8) | (sizeBuf[i*4+3]&0xFF);
                }

                for(blockV=0; blockV<BLOCK_PER_FILE; blockV++) {
                    for(blockH=0; blockH<BLOCK_PER_FILE; blockH++) {
                        blockOffsetV = blockV*FP_PER_BLOCK;
                        blockOffsetH = blockH*FP_PER_BLOCK;
                        reporter.progress();

                        for(fileV=0; fileV<FP_PER_BLOCK; fileV++) {
                            for(fileH=0; fileH<FP_PER_BLOCK; fileH++) {
                                jaccard = jaccardCalc(bfBufV, (blockOffsetV+fileV)*FP_SIZE_INT, codeSizeV[blockOffsetV+fileV], bfBufH, (blockOffsetH+fileH)*FP_SIZE_INT, codeSizeH[blockOffsetH+fileH]);
                                if (jaccard >= THRESHOLD) {
                                    fileNumberV = (dataFileV*FP_PER_FILE)+blockOffsetV+fileV+1;
                                    fileNumberH = (dataFileH*FP_PER_FILE)+blockOffsetH+fileH+1;
                                    //bitShredKey.set(formatter.format(jaccard));
                                    bitShredKey.set(jaccard);
                                    bitShredValue.set(String.format(":%d:%d:", fileNumberV, fileNumberH));
                                    output.collect(bitShredKey, bitShredValue);
                                }
                            }
                        }
                    }
                }
            }
            else {
                for(blockV=0; blockV<BLOCK_PER_FILE; blockV++) {
                    for(blockH=blockV; blockH<BLOCK_PER_FILE; blockH++) {
                        blockOffsetV = blockV*FP_PER_BLOCK;
                        blockOffsetH = blockH*FP_PER_BLOCK;
                        reporter.progress();

                        if(blockV!=blockH) {
                            for(fileV=0; fileV<FP_PER_BLOCK; fileV++) {
                                for(fileH=0; fileH<FP_PER_BLOCK; fileH++) {
                                    jaccard = jaccardCalc(bfBufV, (blockOffsetV+fileV)*FP_SIZE_INT, codeSizeV[blockOffsetV+fileV], bfBufV, (blockOffsetH+fileH)*FP_SIZE_INT, codeSizeV[blockOffsetH+fileH]);
                                    if (jaccard >= THRESHOLD) {
                                        fileNumberV = (dataFileV*FP_PER_FILE)+blockOffsetV+fileV+1;
                                        fileNumberH = (dataFileH*FP_PER_FILE)+blockOffsetH+fileH+1;
                                        //bitShredKey.set(formatter.format(jaccard));
                                        bitShredKey.set(jaccard);
                                        bitShredValue.set(String.format(":%d:%d:", fileNumberV, fileNumberH));
                                        output.collect(bitShredKey, bitShredValue);
                                    }
                                }
                            }
                        }
                        else {
                            for(fileV=0; fileV<FP_PER_BLOCK-1; fileV++) {
                                for(fileH=fileV+1; fileH<FP_PER_BLOCK; fileH++) {
                                    jaccard = jaccardCalc(bfBufV, (blockOffsetV+fileV)*FP_SIZE_INT, codeSizeV[blockOffsetV+fileV], bfBufV, (blockOffsetH+fileH)*FP_SIZE_INT, codeSizeV[blockOffsetH+fileH]);
                                    if (jaccard >= THRESHOLD) {
                                        fileNumberV = (dataFileV*FP_PER_FILE)+blockOffsetV+fileV+1;
                                        fileNumberH = (dataFileH*FP_PER_FILE)+blockOffsetH+fileH+1;
                                        //bitShredKey.set(formatter.format(jaccard));
                                        bitShredKey.set(jaccard);
                                        bitShredValue.set(String.format(":%d:%d:", fileNumberV, fileNumberH));
                                        output.collect(bitShredKey, bitShredValue);
                                    }
                                }
                            }
                        }
                    }
                }
            }

        }

        public static float jaccardCalc(int[] bf1, int offset1, int codeSize1, int[] bf2, int offset2, int codeSize2) {
            int numberSetUnion = 0;
            int numberSetIntersection = 0;
            int tmp;

            for(int i=0; i<FP_SIZE_INT; i++) {
                tmp = bf1[offset1+i] & bf2[offset2+i];

                tmp = tmp - ((tmp >> 1) & 0x55555555);
                tmp = (tmp & 0x33333333) + ((tmp >> 2) & 0x33333333);
                numberSetIntersection += ((tmp + (tmp >> 4) & 0xF0F0F0F) * 0x1010101) >> 24;

                //numberSetUnion += Integer.bitCount(tmp1|tmp2);
            }
            numberSetUnion = codeSize1 + codeSize2 - numberSetIntersection;

            /* With Containment
            if (codeSize1 == codeSize2) {
                numberSetUnion = codeSize1 + codeSize2 - numberSetIntersection;
            }
            else if (codeSize1 < codeSize2) {
                numberSetUnion = codeSize1;
            }
            else {
                numberSetUnion = codeSize2;
            }
            */

            // error handling
            if (numberSetUnion == 0) {
                return 0;
            }
            else {
                return numberSetIntersection / (float)numberSetUnion;
            }
        }
    }

    public static void main(String[] args) throws Exception {
        JobConf conf = new JobConf(Cmp.class);
        conf.setJobName("bitshred_cmp");

        conf.setOutputKeyClass(FloatWritable.class);
        conf.setOutputValueClass(Text.class);
        conf.setInputFormat(TextInputFormat.class);
        conf.setOutputFormat(TextOutputFormat.class);

        conf.setMapperClass(Map.class);
        conf.setNumReduceTasks(8);

        FileInputFormat.setInputPaths(conf, new Path(args[0]));
        FileOutputFormat.setOutputPath(conf, new Path(args[1]));

        JobClient.runJob(conf);
    }
}
