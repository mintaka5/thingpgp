package org.mintaka5.model;

import org.dizitart.no2.IndexType;
import org.dizitart.no2.objects.Id;
import org.dizitart.no2.objects.Index;
import org.dizitart.no2.objects.Indices;
import org.json.JSONObject;

import java.io.Serializable;
import java.util.Base64;

@Indices({
        @Index(value = "hash", type = IndexType.Unique)
})
public class KeyRepo implements Serializable {
    public static final String JSON_HASH_NAME = "hash";
    public static final String JSON_TYPE_NAME = "type";
    public static final String JSON_KEY_NAME = "key";
    public static final String JSON_TIMESTAMP_NAME = "timestamp";
    public static final String JSON_PUBID_NAME = "pubid";

    @Id
    private String hash;
    private int type;
    private byte[] key;
    private long timestamp;
    private long pubId;

    public KeyRepo() {}

    public String getHash() {
        return hash;
    }

    public void setHash(String hash) {
        this.hash = hash;
    }

    public int getType() {
        return type;
    }

    public void setType(int type) {
        this.type = type;
    }

    public byte[] getKey() {
        return key;
    }

    public void setKey(byte[] key) {
        this.key = key;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    public long getPubId() {
        return pubId;
    }

    public void setPubId(long pubId) {
        this.pubId = pubId;
    }

    @Override
    public String toString() {
        JSONObject j = new JSONObject();
        j.put(JSON_HASH_NAME, getHash());
        j.put(JSON_TYPE_NAME, getType());
        j.put(JSON_KEY_NAME, Base64.getEncoder().encodeToString(getKey()));
        j.put(JSON_TIMESTAMP_NAME, getTimestamp());
        j.put(JSON_PUBID_NAME, getPubId());

        return j.toString();
    }
}
