package dev.notegridx.security.assetvulnmanager.utility;

import java.util.LinkedHashMap;
import java.util.Map;

public class LruMap<K, V> extends LinkedHashMap<K, V> {

    private final int maxSize;

    public LruMap(int maxSize) {
        super(16, 0.75f, true);
        this.maxSize = maxSize;
    }

    @Override
    protected synchronized boolean removeEldestEntry(Map.Entry<K, V> eldest) {
        return size() > maxSize;
    }

    @Override
    public synchronized V get(Object key) {
        return super.get(key);
    }

    @Override
    public synchronized V put(K key, V value) {
        return super.put(key, value);
    }
}