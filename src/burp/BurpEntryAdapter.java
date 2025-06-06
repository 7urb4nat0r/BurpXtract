package burp;

import java.net.URL;

public class BurpEntryAdapter implements IHttpRequestResponse {
    private final BurpEntry entry;

    public BurpEntryAdapter(BurpEntry entry) {
        this.entry = entry;
    }

    @Override
    public byte[] getRequest() {
        return entry.getRequest();
    }

    @Override
    public void setRequest(byte[] message) { }

    @Override
    public byte[] getResponse() {
        return entry.getResponse();
    }

    @Override
    public void setResponse(byte[] message) { }

    @Override
    public String getHost() {
        return entry.getHost();
    }

    @Override
    public void setHost(String host) { }

    @Override
    public int getPort() {
        return entry.getPort();
    }

    @Override
    public void setPort(int port) { }

    @Override
    public URL getUrl() {
        try {
            return new URL(entry.getUrl());
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public String getProtocol() {
        try {
            return new URL(entry.getUrl()).getProtocol();
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public void setProtocol(String protocol) { }

    @Override
    public String getComment() { return null; }

    @Override
    public void setComment(String comment) { }

    @Override
    public String getHighlight() { return null; }

    @Override
    public void setHighlight(String highlight) { }

    @Override
    public short getStatusCode() {
        return (short) entry.getStatus();
    }

    @Override
    public void setHttpService(IHttpService httpService) {
        // Not needed for static entries
    }

    // getHttpService() with no @Override in inner methods
    @Override
    public IHttpService getHttpService() {
        return new IHttpService() {
            public String getHost() {
                return entry.getHost();
            }

            public int getPort() {
                return entry.getPort();
            }

            public String getProtocol() {
                try {
                    return new URL(entry.getUrl()).getProtocol();
                } catch (Exception e) {
                    return null;
                }
            }
        };
    }
}
