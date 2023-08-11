package org.mintaka5.model;

import org.dizitart.no2.IndexType;
import org.dizitart.no2.objects.Id;
import org.dizitart.no2.objects.Index;
import org.dizitart.no2.objects.Indices;
import org.json.JSONObject;

import java.io.Serializable;

@Indices({
        @Index(value = "hash", type = IndexType.Unique)
})
public class EncryptedMessageRepo implements Serializable {
    @Id
    private String hash;
    private long timestamp;
    private byte[] message;

    public static final String JSON_HASH_NAME = "hash";
    public static final String JSON_TIMESTAMP_NAME = "timestamp";
    public static final String JSON_MSG_NAME = "message";

    public EncryptedMessageRepo() {}

    public String getHash() {
        return hash;
    }

    public void setHash(String hash) {
        this.hash = hash;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    public byte[] getMessage() {
        return message;
    }

    public void setMessage(byte[] message) {
        this.message = message;
    }

    @Override
    public String toString() {
        JSONObject j = new JSONObject();
        j.put(JSON_HASH_NAME, getHash());
        j.put(JSON_TIMESTAMP_NAME, getTimestamp());
        j.put(JSON_MSG_NAME, getMessage());

        return j.toString();
    }
}
