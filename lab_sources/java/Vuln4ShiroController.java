package com.vuln.app.controller;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.crypto.AesCipherService;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.io.*;

@Controller
@RequestMapping("/vuln4")
public class Vuln4ShiroController {

    private static final Logger log = LoggerFactory.getLogger(Vuln4ShiroController.class);
    private static final String SHIRO_KEY = "kPH+bIxk5D2deZiIxcaaaA==";
    private final AesCipherService cipherService = new AesCipherService();

    @GetMapping("/")
    public String index(Model model) {
        model.addAttribute("vulnName", "Shiro反序列化漏洞");
        model.addAttribute("vulnDesc", "使用Apache Shiro 1.2.4的CVE-2016-4437漏洞");
        model.addAttribute("riskLevel", "高危");
        return "vuln4";
    }

    @PostMapping("/login")
    @ResponseBody
    public String login(@RequestParam String username, @RequestParam String password, HttpServletResponse response) {
        try {
            Subject subject = SecurityUtils.getSubject();
            subject.login(new UsernamePasswordToken(username, password));
            byte[] serialized = serializeData(new UserData(username, System.currentTimeMillis()));
            byte[] encrypted = encryptData(serialized);
            Cookie cookie = new Cookie("rememberMe", Base64.encodeToString(encrypted));
            cookie.setHttpOnly(true);
            cookie.setPath("/");
            response.addCookie(cookie);
            return "登录成功！RememberMe cookie已设置";
        } catch (Exception e) {
            log.error("登录失败", e);
            return "登录失败:" + e.getMessage();
        }
    }

    @GetMapping("/check")
    @ResponseBody
    public String checkRememberMe(@CookieValue(value = "rememberMe", required = false) String rememberMe) {
        if (rememberMe != null) {
            try {
                byte[] encrypted = Base64.decode(rememberMe);
                byte[] decrypted = decryptData(encrypted);
                Object obj = deserializeData(decrypted);
                return "验证成功:" + obj.toString();
            } catch (Exception e) {
                return "验证失败:" + e.getMessage();
            }
        }
        return "No rememberMe cookie";
    }

    private byte[] serializeData(Object obj) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(obj);
        oos.close();
        return bos.toByteArray();
    }

    private Object deserializeData(byte[] data) throws Exception {
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bis);
        Object obj = ois.readObject();
        ois.close();
        return obj;
    }

    private byte[] encryptData(byte[] data) {
        return cipherService.encrypt(data, Base64.decode(SHIRO_KEY)).getBytes();
    }

    private byte[] decryptData(byte[] data) {
        return cipherService.decrypt(data, Base64.decode(SHIRO_KEY)).getBytes();
    }

    public static class UserData implements Serializable {
        private String username;
        private long loginTime;

        public UserData(String username, long loginTime) {
            this.username = username;
            this.loginTime = loginTime;
        }

        @Override
        public String toString() {
            return "UserData{username='" + username + "', loginTime=" + loginTime + "}";
        }
    }
}
