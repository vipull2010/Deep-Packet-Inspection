package dpi;

public class Flow {

    public final FiveTuple tuple;

    public AppType appType  = AppType.UNKNOWN;
    public String  sni      = "";     // SNI hostname or HTTP Host, if found

    public long    packets  = 0;
    public long    bytes    = 0;
    public boolean blocked  = false;  // true = all future packets should be dropped

    public Flow(FiveTuple tuple) {
        this.tuple = tuple;
    }
}
