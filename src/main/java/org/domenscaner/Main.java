package org.domenscaner;

import io.javalin.Javalin;

import java.io.IOException;

public class Main {
    public static void main(String[] args) {
        System.out.println("Hello world!");
        DomenScaner.scan("51.38.24.0/24", 100, "outputFileName");
        Javalin app = Javalin.create(/*config*/)
                .get("/", ctx -> ctx.result("Hello World"))
                .start(8080);
    }
}