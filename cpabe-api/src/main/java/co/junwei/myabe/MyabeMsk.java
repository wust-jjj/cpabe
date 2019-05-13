package co.junwei.myabe;

import it.unisa.dia.gas.jpbc.Element;

import java.util.List;


public class MyabeMsk {
    /*
     * A master secret key
     * mk = (α,t_j (1 ≤ j ≤ n))
     */
    public Element alpha;           /* Z_r */
    List<MyabeMskTj> tj;          /* Z_r */
    public int getTjIndex(String attr){
        for(int i=0;i<tj.size();i++){
            if(attr.equals(tj.get(i).attr))
                return i;
        }
        return -1;
    }
}
