package com.vuln.app.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/vuln3")
public class Vuln3JacksonController {

    private static final Logger log = LoggerFactory.getLogger(Vuln3JacksonController.class);

    @GetMapping("/")
    public String index(Model model) {
        model.addAttribute("vulnName", "Jackson反序列化漏洞");
        model.addAttribute("vulnDesc", "使用Jackson 2.9.8的CVE-2017-7525漏洞");
        model.addAttribute("riskLevel", "中高危");
        return "vuln3";
    }

    @PostMapping("/deserialize")
    @ResponseBody
    public String deserialize(@RequestBody String jsonData) {
        return "Jackson反序列化功能暂时禁用，需要配置Jackson依赖";
    }

    @GetMapping("/data")
    @ResponseBody
    public String getData(@RequestParam String data) {
        return "Jackson数据解析功能暂时禁用，需要配置Jackson依赖";
    }

    @PostMapping("/settings")
    @ResponseBody
    public String updateSettings(@RequestBody String jsonData) {
        return "Jackson设置功能暂时禁用，需要配置Jackson依赖";
    }
}
