package com.ua.passlocker.authorizer.security;

public class AppContextHolder {

    private static ThreadLocal<String> threadLocal = new ThreadLocal<>();

    public static void setThreadLocal(String secret) {
        threadLocal.set(secret);
    }

    public static String getThreadLocal() {
        return threadLocal.get();
    }

    public static void clearThreadLocal() {
        threadLocal.remove();
    }
}
