package co.junwei.myabe;

import java.io.*;

public class Common {
    /* read byte[] from inputfile */
    public static byte[] suckFile(String inputfile) throws IOException {
        InputStream is = new FileInputStream(inputfile);
        int size = is.available();
        byte[] content = new byte[size];

        is.read(content);

        is.close();
        return content;
    }

    /* write byte[] into outputfile */
    public static void spitFile(String outputfile, byte[] b) throws IOException {
        OutputStream os = new FileOutputStream(outputfile);
        os.write(b);
        os.close();
    }
    public static byte[][] readCpabeFile(String encfile) throws IOException {
        int i, len;
        InputStream is = new FileInputStream(encfile);
        byte[][] res = new byte[2][];
        byte[] aesBuf, cphBuf;

        /* read aes buf */
        len = 0;
        for (i = 3; i >= 0; i--)
            len |= is.read() << (i * 8);
        aesBuf = new byte[len];

        is.read(aesBuf);

        /* read cph buf */
        len = 0;
        for (i = 3; i >= 0; i--)
            len |= is.read() << (i * 8);
        cphBuf = new byte[len];

        is.read(cphBuf);

        is.close();

        res[0] = aesBuf;
        res[1] = cphBuf;
        return res;
    }
    public static void writeCpabeFile(String encfile,
                                      byte[] cphBuf, byte[] aesBuf) throws IOException {
        int i;
        OutputStream os = new FileOutputStream(encfile);

        /* write aes_buf */
        for (i = 3; i >= 0; i--)
            os.write(((aesBuf.length & (0xff << 8 * i)) >> 8 * i));
        os.write(aesBuf);

        /* write cph_buf */
        for (i = 3; i >= 0; i--)
            os.write(((cphBuf.length & (0xff << 8 * i)) >> 8 * i));
        os.write(cphBuf);

        os.close();

    }
}
