package co.junwei.myabe;

import it.unisa.dia.gas.jpbc.CurveParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.DefaultCurveParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;

public class Myabe {
    /*
     * Generate a public key and corresponding master secret key.
     */
    private static String curveParams = "type a\n"
            + "q 87807107996633125224377819847540498158068831994142082"
            + "1102865339926647563088022295707862517942266222142315585"
            + "8769582317459277713367317481324925129998224791\n"
            + "h 12016012264891146079388821366740534204802954401251311"
            + "822919615131047207289359704531102844802183906537786776\n"
            + "r 730750818665451621361119245571504901405976559617\n"
            + "exp2 159\n" + "exp1 107\n" + "sign1 1\n" + "sign0 1\n";

    public static void setup(MyabePub pub, MyabeMsk msk, String[] attrs) {

        Element g_alpha;

        CurveParameters params = new DefaultCurveParameters()
                .load(new ByteArrayInputStream(curveParams.getBytes()));

        pub.pairingDesc = curveParams;
        pub.p = PairingFactory.getPairing(params);
        Pairing pairing = pub.p;

        g_alpha = pairing.getG1().newElement();
        pub.g = pairing.getG1().newElement();
        pub.y = pairing.getGT().newElement();

        msk.alpha = pairing.getZr().newElement();

        msk.alpha.setToRandom();

        pub.g.setToRandom();
        g_alpha.set(pub.g.duplicate());

        g_alpha = g_alpha.powZn(msk.alpha);
        pub.y = pairing.pairing(pub.g, g_alpha);

        int i, len = attrs.length;

        msk.tj = new ArrayList<MyabeMskTj>();
        for (i = 0; i < len; i++) {
            MyabeMskTj tj = new MyabeMskTj();

            Element t = pairing.getZr().newElement();
            t.setToRandom();
            tj.tj = pairing.getZr().newElement();
            tj.tj = t.duplicate();
            tj.attr = attrs[i];
            msk.tj.add(tj);
        }

        pub.t_j = new ArrayList<MyabePubT>();
        for (i = 0; i < len; i++) {
            MyabePubT t = new MyabePubT();
            MyabeMskTj tj = msk.tj.get(i);
            t.attr = tj.attr;
            t.tj = pairing.getG1().newElement();
            t.tj = pub.g.duplicate();
            t.tj.powZn(tj.tj);
            pub.t_j.add(t);
        }

    }
    /*
     * Generate a private key with the given set of attributes.
     */
    public static MyabePrv keygen(MyabePub pub, MyabeMsk msk, String[] attrs)
            throws NoSuchAlgorithmException {
        Element r,rt,g_alpha,g_r;
        Pairing pairing = pub.p;
        MyabePrv prv = new MyabePrv();

        r = pairing.getZr().newElement();
        rt = pairing.getZr().newElement();
        g_r= pairing.getG1().newElement();
        g_alpha= pairing.getG1().newElement();

        r.setToRandom();

        g_r = pub.g.duplicate();
        g_r.powZn(r);

        g_alpha = pub.g.duplicate();
        g_alpha.powZn(msk.alpha);

        prv.d = pairing.getG1().newElement();
        prv.d = g_alpha.duplicate();
        prv.d.div(g_r);

        int i, len = attrs.length;
        prv.dj = new ArrayList<MyabePrvD>();

        for (i = 0; i < len; i++) {
            if(msk.getTjIndex(attrs[i]) == -1){
                continue;
            }
            else{
                MyabeMskTj tj = msk.tj.get(msk.getTjIndex(attrs[i]));
                MyabePrvD d = new MyabePrvD();
                d.attr = tj.attr;
                d.d = pairing.getG1().newElement();
                rt = r.duplicate();
                rt.mul(msk.tj.get(i).tj.invert());
                d.d = pub.g.duplicate();
                d.d.powZn(rt);
                prv.dj.add(d);
            }
        }
        return prv;

    }
    /*
     * Pick a random group element and encrypt it under the specified access
     * policy. The resulting ciphertext is returned and the Element given as an
     * argument (which need not be initialized) is set to the random group
     * element.
     *
     * After using this function, it is normal to extract the random data in m
     * using the pbc functions element_length_in_bytes and element_to_bytes and
     * use it as a key for hybrid encryption.
     *
     * The policy is specified as a simple string which encodes a postorder
     * traversal of threshold tree defining the access policy. As an example,
     *
     * "foo bar fim 2of3 baf 1of2"
     *
     * specifies a policy with two threshold gates and four leaves. It is not
     * possible to specify an attribute with whitespace in it (although "_" is
     * allowed).
     *
     * Numerical attributes and any other fancy stuff are not supported.
     *
     * Returns null if an error occured, in which case a description can be
     * retrieved by calling Myabe_error().
     */
    public static MyabeCphKey enc(MyabePub pub, String policy)
            throws Exception {
        MyabeCphKey keyCph = new MyabeCphKey();
        MyabeCph cph = new MyabeCph();
        Element s, m;

        /* initialize */
        Pairing pairing = pub.p;
        s = pairing.getZr().newElement();
        m = pairing.getGT().newElement();
        cph.cs = pairing.getGT().newElement();
        cph.c = pairing.getG1().newElement();

        cph.p = parsePolicyPostfix(policy); //构造属性访问树

        /* compute */
        m.setToRandom();
        s.setToRandom();
        cph.cs = pub.y.duplicate();
        cph.cs.powZn(s); /* num_exps++; */
        cph.cs.mul(m); /* num_muls++; */

        cph.c = pub.g.duplicate();
        cph.c.powZn(s); /* num_exps++; */

        fillPolicy(cph.p, pub, s);  //填写叶子节点策略

        keyCph.cph = cph;
        keyCph.key = m;

        return keyCph;
    }

    public static MyabeElementBoolean dec(MyabePub pub, MyabePrv prv,
                                           MyabeCph cph) {
        Element t,tp;
        Element m;
        MyabeElementBoolean beb = new MyabeElementBoolean();

        m = pub.p.getGT().newElement();
        t = pub.p.getGT().newElement();
        tp = pub.p.getGT().newElement();

        checkSatisfy(cph.p, prv);

        if (!cph.p.satisfiable) {
            System.err.println("cannot decrypt, attributes in key do not satisfy policy");
            beb.e = null;
            beb.b = false;
            return beb;
        }

        pickSatisfyMinLeaves(cph.p, prv);//没看懂，选择最小满足树

        decFlatten(t, cph.p, prv, pub);

        tp = pub.p.pairing(cph.c, prv.d);

        t.mul(tp);

        m = cph.cs.div(t);

        beb.e = m;
        beb.b = true;

        return beb;
    }

    private static void checkSatisfy(MyabePolicy p, MyabePrv prv) {
        int i, l;
        String prvAttr;

        p.satisfiable = false;

        if (p.children == null || p.children.length == 0) {
            for (i = 0; i < prv.dj.size(); i++) {
                prvAttr = prv.dj.get(i).attr;
                // System.out.println("prvAtt:" + prvAttr);
                // System.out.println("p.attr" + p.attr);
                if (prvAttr.compareTo(p.attr) == 0) {
                    // System.out.println("=staisfy=");
                    p.satisfiable = true;
                    p.attri = i;
                    break;
                }
            }
        } else {
            for (i = 0; i < p.children.length; i++)
                checkSatisfy(p.children[i], prv);

            l = 0;
            for (i = 0; i < p.children.length; i++)
                if (p.children[i].satisfiable)
                    l++;

            if (l >= p.k)
                p.satisfiable = true;
        }
    }

    private static void pickSatisfyMinLeaves(MyabePolicy p, MyabePrv prv) {
        int i, k, l, c_i;
        int len;
        ArrayList<Integer> c = new ArrayList<Integer>();

        if (p.children == null || p.children.length == 0)
            p.min_leaves = 1;
        else {
            len = p.children.length;
            for (i = 0; i < len; i++)
                if (p.children[i].satisfiable)
                    pickSatisfyMinLeaves(p.children[i], prv);

            for (i = 0; i < len; i++)
                c.add(new Integer(i));

            Collections.sort(c, new IntegerComparator(p));  //对children.min_leaves从小到大进行排序

            p.satl = new ArrayList<Integer>();
            p.min_leaves = 0;
            l = 0;

            for (i = 0; i < len && l < p.k; i++) {
                c_i = c.get(i).intValue(); /* c[i] */
                if (p.children[c_i].satisfiable) {
                    l++;
                    p.min_leaves += p.children[c_i].min_leaves;
                    k = c_i + 1;
                    p.satl.add(new Integer(k));
                }
            }
        }
    }

    private static class IntegerComparator implements Comparator<Integer> {
        MyabePolicy policy;

        public IntegerComparator(MyabePolicy p) {
            this.policy = p;
        }

        @Override
        public int compare(Integer o1, Integer o2) {
            int k, l;

            k = policy.children[o1.intValue()].min_leaves;
            l = policy.children[o2.intValue()].min_leaves;

            return	k < l ? -1 :
                    k == l ? 0 : 1;//返回1系统就会识别是前者大于后者,返回-1系统就会识别是前者小于后者，返回0表示相等
        }
    }

    private static void decFlatten(Element r, MyabePolicy p, MyabePrv prv,
                                   MyabePub pub) {
        Element one;
        one = pub.p.getZr().newElement();
        one.setToOne();
        r.setToOne();

        decNodeFlatten(r, one, p, prv, pub);
    }

    private static void decNodeFlatten(Element r, Element exp, MyabePolicy p,
                                       MyabePrv prv, MyabePub pub) {
        if (p.children == null || p.children.length == 0)
            decLeafFlatten(r, exp, p, prv, pub);//叶子节点
        else
            decInternalFlatten(r, exp, p, prv, pub);    //非叶子节点
    }

    private static void decLeafFlatten(Element r, Element exp, MyabePolicy p,
                                       MyabePrv prv, MyabePub pub) {
        MyabePrvD c;
        Element s, t;

        c = prv.dj.get(p.attri);

        s = pub.p.getGT().newElement();
        t = pub.p.getGT().newElement();

        //s = pub.p.pairing(p.c, c.d); /* num_pairings++; */
        //t = pub.p.pairing(p.cp, c.dp); /* num_pairings++; */
        s = pub.p.pairing(p.cji, c.d);

        s.powZn(exp); /* num_exps++; */

        r.mul(s); /* num_muls++; */
    }

    private static void decInternalFlatten(Element r, Element exp,
                                           MyabePolicy p, MyabePrv prv, MyabePub pub) {
        int i;
        Element t, expnew;

        t = pub.p.getZr().newElement();
        expnew = pub.p.getZr().newElement();

        for (i = 0; i < p.satl.size(); i++) {
            lagrangeCoef(t, p.satl, (p.satl.get(i)).intValue());
            expnew = exp.duplicate();
            expnew.mul(t);
            decNodeFlatten(r, expnew, p.children[p.satl.get(i) - 1], prv, pub);
        }
    }

    private static void lagrangeCoef(Element r, ArrayList<Integer> s, int i) {
        int j, k;
        Element t;

        t = r.duplicate();

        r.setToOne();
        for (k = 0; k < s.size(); k++) {
            j = s.get(k).intValue();
            if (j == i)
                continue;
            t.set(-j);
            r.mul(t); /* num_muls++; */
            t.set(i - j);
            t.invert();
            r.mul(t); /* num_muls++; */
        }
    }

    private static MyabePolicy parsePolicyPostfix(String s)
            throws Exception {
        String[] toks;
        String tok;
        ArrayList<MyabePolicy> stack = new ArrayList<MyabePolicy>();
        MyabePolicy root;

        toks = s.split(" ");

        int toks_cnt = toks.length;
        for (int index = 0; index < toks_cnt; index++) {
            int i, k, n;

            tok = toks[index];
            if (!tok.contains("of")) {  //这里要注意，结构树中属性不能含有“of”字段
                stack.add(baseNode(1, tok));
            } else {
                MyabePolicy node;

                /* parse kof n node */
                String[] k_n = tok.split("of");
                k = Integer.parseInt(k_n[0]);
                n = Integer.parseInt(k_n[1]);

                if (k < 1) {
                    System.out.println("error parsing " + s
                            + ": trivially satisfied operator " + tok);
                    return null;
                } else if (k > n) {
                    System.out.println("error parsing " + s
                            + ": unsatisfiable operator " + tok);
                    return null;
                } else if (n == 1) {
                    System.out.println("error parsing " + s
                            + ": indentity operator " + tok);
                    return null;
                } else if (n > stack.size()) {
                    System.out.println("error parsing " + s
                            + ": stack underflow at " + tok);
                    return null;
                }

                /* pop n things and fill in children */
                node = baseNode(k, null);
                node.children = new MyabePolicy[n];

                for (i = n - 1; i >= 0; i--)    //用出栈元素来构造子树
                    node.children[i] = stack.remove(stack.size() - 1);

                /* push result */
                stack.add(node);
            }
        }

        if (stack.size() > 1) {
            System.out.println("error parsing " + s
                    + ": extra node left on the stack");
            return null;
        } else if (stack.size() < 1) {
            System.out.println("error parsing " + s + ": empty policy");
            return null;
        }

        root = stack.get(0);
        return root;
    }
    private static MyabePolicy baseNode(int k, String s) {
        MyabePolicy p = new MyabePolicy();

        p.k = k;
        if (!(s == null))
            p.attr = s;
        else
            p.attr = null;
        p.q = null;

        return p;
    }

    private static void fillPolicy(MyabePolicy p, MyabePub pub, Element e)
            throws NoSuchAlgorithmException {
        int i;
        int index = 1;
        Element r, t, h;
        Pairing pairing = pub.p;
        r = pairing.getZr().newElement();
        t = pairing.getZr().newElement();
        h = pairing.getG1().newElement();

        p.q = randPoly(p.k - 1, e);//构造k - 1阶的多项式系数, e是常数项，即秘密值s

        /*for(int ii=0;ii<pub.t_j.size();ii++){
            System.err.println(pub.t_j.get(ii).attr);
        }*/

        if (p.children == null || p.children.length == 0) { //叶子节点
            if(pub.getTjIndex(p.attr) != -1){
                p.c = pairing.getG1().newElement();
                p.cp = pairing.getG1().newElement();
                p.cji = pairing.getG1().newElement();
                p.cji = pub.t_j.get(pub.getTjIndex(p.attr)).tj;
                p.cji.powZn(p.si);
            }
            else{
                System.err.println("the policy\"" + p.attr +  "\" attributes is not recognized");
            }
        } else {    //非叶子节点
            for (i = 0; i < p.children.length; i++) {
                r.set(i + 1);
                evalPoly(t, p, r);//计算多项式的值，t为结果，r为序号，即t=f(t)
                p.children[i].si = pairing.getG1().newElement();
                p.children[i].si = t.duplicate();   //为每个非叶子节点分配的秘密值
                fillPolicy(p.children[i], pub, t);
            }
        }
    }


    private static void evalPoly(Element r, MyabePolicy q, Element x) {
        int i;
        Element s, t;

        s = r.duplicate();
        t = r.duplicate();

        r.setToZero();
        t.setToOne();

        for (i = 0; i < q.q.deg + 1; i++) {
            //计算拉格朗日多项式：r = coef[0] + coef[1]*x + coef[2]*x^2...
            /* r += q->coef[i] * t */
            s = q.q.coef[i].duplicate();
            s.mul(t);
            r.add(s);

            /* t *= x */
            t.mul(x);
        }

    }

    private static MyabePolynomial randPoly(int deg, Element zeroVal) { //构造deg阶的多项式系数
        int i;
        MyabePolynomial q = new MyabePolynomial();
        q.deg = deg;
        q.coef = new Element[deg + 1];

        for (i = 0; i < deg + 1; i++)
            q.coef[i] = zeroVal.duplicate();

        q.coef[0].set(zeroVal);

        for (i = 1; i < deg + 1; i++)
            q.coef[i].setToRandom();

        return q;
    }
    private static void elementFromString(Element h, String s)
            throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] digest = md.digest(s.getBytes());
        h.setFromHash(digest, 0, digest.length);
    }


}
