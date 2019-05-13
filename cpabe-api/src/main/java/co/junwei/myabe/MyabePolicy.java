package co.junwei.myabe;

import it.unisa.dia.gas.jpbc.Element;
import java.util.ArrayList;

public class MyabePolicy {
    /* serialized */

    /* k=1 if leaf, otherwise threshould */
    /*叶子节点为1，非叶子节点为其门限值*/
    int k;
    /* attribute string if leaf, otherwise null */
    String attr;
    Element c;		/* G_1 only for leaves */
    Element cp;		/* G_1 only for leaves */
    Element cji;    /* G_1 only for leaves */

    /* array of MyabePolicy and length is 0 for leaves */
    MyabePolicy[] children;

    /* only used during encryption */
    /* 用于存放拉格朗日系数*/
    MyabePolynomial q;
    /* 用于存叶子节点的秘密*/
    Element si;

    /* only used during decription */
    boolean satisfiable;
    int min_leaves;
    int attri;
    ArrayList<Integer> satl = new ArrayList<Integer>();
}
