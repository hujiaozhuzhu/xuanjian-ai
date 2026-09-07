package com.vuln.app.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.util.Base64;

@Controller
@RequestMapping("/vuln1")
public class Vuln1NativeDeserializationController {

    private static final Logger log = LoggerFactory.getLogger(Vuln1NativeDeserializationController.class);

    @GetMapping("/")
    public String index(Model model) {
        model.addAttribute("vulnName", "Java原生反序列化漏洞");
        model.addAttribute("vulnDesc", "使用Apache Commons Collections 3.1的Java原生反序列化漏洞");
        model.addAttribute("riskLevel", "高危");
        return "vuln1";
    }

    @PostMapping("/deserialize")
    @ResponseBody
    public String deserialize(@RequestBody String data, HttpServletResponse response) {
        try {
            byte[] bytes = Base64.getDecoder().decode(data);
            ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
            ObjectInputStream ois = new ObjectInputStream(bis);
            Object obj = ois.readObject();
            ois.close();
            return "反序列化成功！对象:" + obj.toString();
        } catch (Exception e) {
            log.error("反序列化失败", e);
            return "反序列化失败:" + e.getMessage();
        }
    }

    @GetMapping("/cookie")
    @ResponseBody
    public String cookieVuln(@CookieValue(value = "user", required = false) String cookie, HttpServletResponse response) {
        if (cookie != null) {
            try {
                byte[] bytes = Base64.getDecoder().decode(cookie);
                ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
                ObjectInputStream ois = new ObjectInputStream(bis);
                Object obj = ois.readObject();
                ois.close();
                return "Cookie反序列化成功:" + obj.toString();
            } catch (Exception e) {
                return "Cookie反序列化失败:" + e.getMessage();
            }
        }
        return "No cookie found";
    }

    @PostMapping("/profile")
    @ResponseBody
    public String updateProfile(@RequestBody String data) {
        try {
            byte[] bytes = Base64.getDecoder().decode(data);
            ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
            ObjectInputStream ois = new ObjectInputStream(bis);
            Object obj = ois.readObject();
            ois.close();
            return "Profile更新成功:" + obj.toString();
        } catch (Exception e) {
            return "Profile更新失败:" + e.getMessage();
        }
    }
}
