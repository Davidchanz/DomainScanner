package org.domenscaner;

import io.javalin.Javalin;
import io.javalin.http.staticfiles.Location;
import io.javalin.plugin.rendering.JavalinRenderer;
import io.javalin.plugin.rendering.template.JavalinThymeleaf;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.*;

import static io.javalin.plugin.rendering.template.TemplateUtil.model;

public class Main {
    public static void main(String[] args) {
        Javalin app = Javalin.create(config -> {
                    config.addStaticFiles("/static", Location.CLASSPATH);
                    JavalinRenderer.register(JavalinThymeleaf.INSTANCE);
                })
                .get("/", ctx ->{
                    try {
                        ctx.render("/templates/home.html", model("ip", "", "threadNum", 1));
                    }catch (Exception e){
                        ctx.redirect("/", 400);
                    }
                })
                .start(8080);
        app.post("/scan", ctx -> {
            try {
                String IP = ctx.formParam("ip");
                int threadNum = Integer.parseInt(ctx.formParam("threadNum"));
                String fileName = File.createTempFile("IPAddresses_Domains_", ".txt").getName();
                List<String> result = DomenScaner.scan(IP, threadNum, fileName);
                ctx.render("/templates/home.html", model(
                        "ip", IP
                        , "threadNum", threadNum
                        , "filename", fileName
                        , "addresses", result.isEmpty() ? "empty" : result)
                );
            }catch (Exception e){
                ctx.redirect("/", 400);
            }
        });

        app.get("/download/{filename}", ctx -> {
            try {
                File localFile = new File(ctx.pathParam("filename"));
                InputStream inputStream = new BufferedInputStream(new FileInputStream(localFile));
                ctx.header("Content-Disposition", "attachment; filename=\"" + localFile.getName() + "\"");
                ctx.header("Content-Length", String.valueOf(localFile.length()));
                ctx.result(inputStream);
            }catch (Exception e){
                ctx.redirect("/", 400);
            }
        });

        app.error(400, "html", ctx -> {
            ctx.result("BAD REQUEST!");
        });
    }
}