package jni;

public class PrivateDataHandler {
    private Object privateData;
    
    protected PrivateDataHandler(Object data) {
        privateData = data;
    }
    
    public int hashCode() {
        return privateData.hashCode();
    }
    
    public String stringHashCode() {
        return String.valueOf(hashCode());
    }
    
    public Object getData() {
        return privateData;
    }
}

