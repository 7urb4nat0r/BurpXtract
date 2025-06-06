package burp;

public class BurpEntry {
    private final String method;
    private final String url;
    private final String host;
    private final int port;
    private final boolean https;
    private final byte[] request;
    private final byte[] response;
    private final int status;
    private final int length;
    private final String mimeType;
    private final String ip;

    public BurpEntry(String method, String url, String host, int port, boolean https, byte[] request, byte[] response, int status, int length, String mimeType, String ip) {
        this.method = method;
        this.url = url;
        this.host = host;
        this.port = port;
        this.https = https;
        this.request = request;
        this.response = response;
        this.status = status;
        this.length = length;
        this.mimeType = mimeType;
        this.ip = ip;
    }

    public String getMethod()     { return method; }
    public String getUrl()        { return url; }
    public String getHost()       { return host; }
    public int getPort()          { return port; }
    public boolean isHttps()      { return https; }
    public byte[] getRequest()    { return request; }
    public byte[] getResponse()   { return response; }
    public int getStatus()        { return status; }
    public int getLength()        { return length; }
    public String getMimeType()   { return mimeType; }
    public String getIp()         { return ip; }
}
