package co.junwei.myabe;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.List;

public class MyabePub {
    /*
     * A public key
     *
     * pk = (ê,g,y,T_j(1 ≤ j ≤ n))
     * y = ê(g,g)^α
     * T_j = g^t_j
     */
    public String pairingDesc;
    public Pairing p;

    public Element g;				/* G_1 */
    public Element y;				/* G_T */
    List<MyabePubT> t_j;       /* MyabePubT */
    public int getTjIndex(String attr){
        for(int i=0;i<t_j.size();i++){
            if(attr.equals(t_j.get(i).attr))
                return i;
        }
        return -1;
    }

    //public Element h;				/* G_1 */
    //public Element f;				/* G_1 */
   // public Element gp;			/* G_2 */
    //public Element g_hat_alpha;	/* G_T */
}
