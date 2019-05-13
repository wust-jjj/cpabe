package co.junwei.myabe;

import it.unisa.dia.gas.jpbc.CurveParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.DefaultCurveParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.ByteArrayInputStream;
import java.util.ArrayList;

public class SerializeUtils {
    /* Method has been test okay */
    public static void serializeElement(ArrayList<Byte> arrlist, Element e) {
        byte[] arr_e = e.toBytes();
        serializeUint32(arrlist, arr_e.length);
        byteArrListAppend(arrlist, arr_e);
    }

    /* Method has been test okay */
    public static int unserializeElement(byte[] arr, int offset, Element e) {
        int len;
        int i;
        byte[] e_byte;

        len = unserializeUint32(arr, offset);
        e_byte = new byte[(int) len];
        offset += 4;
        for (i = 0; i < len; i++)
            e_byte[i] = arr[offset + i];
        e.setFromBytes(e_byte);

        return (int) (offset + len);
    }

    public static void serializeString(ArrayList<Byte> arrlist, String s) {
        byte[] b = s.getBytes();
        serializeUint32(arrlist, b.length);
        byteArrListAppend(arrlist, b);
    }

    /*
     * Usage:
     *
     * StringBuffer sb = new StringBuffer("");
     *
     * offset = unserializeString(arr, offset, sb);
     *
     * String str = sb.substring(0);
     */
    public static int unserializeString(byte[] arr, int offset, StringBuffer sb) {
        int i;
        int len;
        byte[] str_byte;

        len = unserializeUint32(arr, offset);
        offset += 4;
        str_byte = new byte[len];
        for (i = 0; i < len; i++)
            str_byte[i] = arr[offset + i];

        sb.append(new String(str_byte));
        return offset + len;
    }

    public static byte[] MyabeCphSerialize(MyabeCph cph) {
        ArrayList<Byte> arrlist = new ArrayList<Byte>();
        SerializeUtils.serializeElement(arrlist, cph.cs);
        SerializeUtils.serializeElement(arrlist, cph.c);
        SerializeUtils.serializePolicy(arrlist, cph.p);

        return Byte_arr2byte_arr(arrlist);
    }

    public static MyabeCph MyabeCphUnserialize(MyabePub pub, byte[] cphBuf) {
        MyabeCph cph = new MyabeCph();
        int offset = 0;
        int[] offset_arr = new int[1];

        cph.cs = pub.p.getGT().newElement();
        cph.c = pub.p.getG1().newElement();


        offset = SerializeUtils.unserializeElement(cphBuf, offset, cph.cs);
        offset = SerializeUtils.unserializeElement(cphBuf, offset, cph.c);

        offset_arr[0] = offset;
        cph.p = SerializeUtils.unserializePolicy(pub, cphBuf, offset_arr);
        offset = offset_arr[0];

        return cph;
    }

    /* Method has been test okay */
    /* potential problem: the number to be serialize is less than 2^31 */
    private static void serializeUint32(ArrayList<Byte> arrlist, int k) {
        int i;
        byte b;

        for (i = 3; i >= 0; i--) {
            b = (byte) ((k & (0x000000ff << (i * 8))) >> (i * 8));
            arrlist.add(Byte.valueOf(b));
        }
    }

    /*
     * Usage:
     *
     * You have to do offset+=4 after call this method
     */
    /* Method has been test okay */
    private static int unserializeUint32(byte[] arr, int offset) {
        int i;
        int r = 0;

        for (i = 3; i >= 0; i--)
            r |= (byte2int(arr[offset++])) << (i * 8);
        return r;
    }

    private static void serializePolicy(ArrayList<Byte> arrlist, MyabePolicy p) {
        serializeUint32(arrlist, p.k);

        if (p.children == null || p.children.length == 0) {
            serializeUint32(arrlist, 0);
            serializeString(arrlist, p.attr);
            serializeElement(arrlist, p.c);
            serializeElement(arrlist, p.cp);
            serializeElement(arrlist, p.cji);
        } else {
            serializeUint32(arrlist, p.children.length);
            for (int i = 0; i < p.children.length; i++)
                serializePolicy(arrlist, p.children[i]);
        }
    }

    private static MyabePolicy unserializePolicy(MyabePub pub, byte[] arr,
                                                  int[] offset) {
        int i;
        int n;
        MyabePolicy p = new MyabePolicy();
        p.k = unserializeUint32(arr, offset[0]);
        offset[0] += 4;
        p.attr = null;

        /* children */
        n = unserializeUint32(arr, offset[0]);
        offset[0] += 4;
        if (n == 0) {
            p.children = null;

            StringBuffer sb = new StringBuffer("");
            offset[0] = unserializeString(arr, offset[0], sb);
            p.attr = sb.substring(0);

            p.c = pub.p.getG1().newElement();
            p.cp = pub.p.getG1().newElement();
            p.cji = pub.p.getG1().newElement();

            offset[0] = unserializeElement(arr, offset[0], p.c);
            offset[0] = unserializeElement(arr, offset[0], p.cp);
            offset[0] = unserializeElement(arr, offset[0], p.cji);
        } else {
            p.children = new MyabePolicy[n];
            for (i = 0; i < n; i++)
                p.children[i] = unserializePolicy(pub, arr, offset);
        }

        return p;
    }

    private static int byte2int(byte b) {
        if (b >= 0)
            return b;
        return (256 + b);
    }

    private static void byteArrListAppend(ArrayList<Byte> arrlist, byte[] b) {
        int len = b.length;
        for (int i = 0; i < len; i++)
            arrlist.add(Byte.valueOf(b[i]));
    }

    private static byte[] Byte_arr2byte_arr(ArrayList<Byte> B) {
        int len = B.size();
        byte[] b = new byte[len];

        for (int i = 0; i < len; i++)
            b[i] = B.get(i).byteValue();

        return b;
    }
}
