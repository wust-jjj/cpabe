package co.junwei.myabe;


import it.unisa.dia.gas.jpbc.Element;

import java.security.NoSuchAlgorithmException;

public class MyabeTools {

    public void setup(MyabePub pub, MyabeMsk msk, String attr_str){
        String[] attr_arr = LangPolicy.parseAttribute(attr_str);
        Myabe.setup(pub, msk, attr_arr);
    }

    public MyabePrv keygen(MyabePub pub, MyabeMsk msk, String attr_str) throws NoSuchAlgorithmException{

        String[] attr_arr = LangPolicy.parseAttribute(attr_str);
        MyabePrv prv = Myabe.keygen(pub, msk, attr_arr);
        return prv;
    }
    public void enc(MyabePub pub, String policy, String inputfile,
                    String encfile) throws Exception {
        MyabeCph cph;
        MyabeCphKey keyCph;
        byte[] plt;
        byte[] cphBuf;
        byte[] aesBuf;
        Element m;

        keyCph = Myabe.enc(pub, policy);
        cph = keyCph.cph;
        m = keyCph.key;
        System.err.println("m = " + m.toString());

        if (cph == null) {
            System.out.println("Error happed in enc");
            System.exit(0);
        }

        cphBuf = SerializeUtils.MyabeCphSerialize(cph);

        /* read file to encrypted */
        plt = Common.suckFile(inputfile);

        aesBuf = AESCoder.encrypt(m.toBytes(), plt);
        // PrintArr("element: ", m.toBytes());
        Common.writeCpabeFile(encfile, cphBuf, aesBuf);
    }
    public void dec(MyabePub pub, MyabePrv prv, String encfile,
                    String decfile) throws Exception {
        byte[] aesBuf, cphBuf;
        byte[] plt;
        byte[][] tmp;
        MyabeCph cph;


        /* read ciphertext */
        tmp = Common.readCpabeFile(encfile);
        aesBuf = tmp[0];
        cphBuf = tmp[1];
        cph = SerializeUtils.MyabeCphUnserialize(pub, cphBuf);

        MyabeElementBoolean beb = Myabe.dec(pub, prv, cph);
        System.err.println("e = " + beb.e.toString());
        if (beb.b) {
            plt = AESCoder.decrypt(beb.e.toBytes(), aesBuf);
            // plt = AESCoder.decrypt(beb.e.toBytes(), aesBuf);
            Common.spitFile(decfile, plt);
        } else {
            System.exit(0);
        }
    }
}
