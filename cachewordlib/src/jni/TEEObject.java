package jni;

public class TEEObject {
    private Object privateData;
    
    protected TEEObject(Object data) {
        privateData = data;
    }
    
    public int hashCode() {
        return privateData.hashCode();
    }
    
    public String stringHashCode() {
        return String.valueOf(hashCode());
    }
    
    protected Object getData() {
        return privateData;
    }
}

