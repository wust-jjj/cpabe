package co.junwei.myabe;

import it.unisa.dia.gas.jpbc.Element;

import java.util.List;

public class MyabePrv {
    /*
     * A private key
     *  sk_ω = (d_0 ,∀a_j ∈ ω : d_j )
     *  d_0 = g^(α−r)
     *   d_j = g^((rt_j)^-1
     */
    Element d;                /* G_1 */
    List<MyabePrvD> dj;     /* MyabePrvD */
    public int getDjIndex(String attr){
        for(int i=0;i<dj.size();i++){
            if(attr.equals(dj.get(i).attr))
                return i;
        }
        return -1;
    }
}
