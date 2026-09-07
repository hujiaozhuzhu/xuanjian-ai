
package com.vuln;

import com.fasterxml.jackson.databind.ObjectMapper;
import static spark.Spark.*;

public class JacksonVulnService {
    
    public static void main(String[] args) {
        port(8081);
        
        // Vulnerable endpoint - uses Jackson with default typing enabled
        post("/parse", (req, res) -> {
            res.type("application/json");
            try {
                String jsonInput = req.body();
                if (jsonInput == null || jsonInput.isEmpty()) {
                    return "{"error": "Empty body"}";
                }
                
                // VULNERABLE: enableDefaultTyping allows class instantiation from JSON
                ObjectMapper mapper = new ObjectMapper();
                mapper.enableDefaultTyping();
                
                // Deserialize JSON with polymorphic type handling
                Object result = mapper.readValue(jsonInput, Object.class);
                
                return "{"status": "parsed", "result": " + mapper.writeValueAsString(result) + "}";
            } catch (Exception e) {
                return "{"error": "" + e.getMessage() + ""}";
            }
        });
        
        // Health check
        get("/health", (req, res) -> {
            res.type("application/json");
            return "{"status": "ok", "jackson": "2.9.8", "vulnerable": true}";
        });
        
        // Info page
        get("/", (req, res) -> {
            res.type("text/html");
            return "<html><body>" +
                "<h1>Jackson CVE-2017-7525 Vulnerable Service</h1>" +
                "<p>Version: Jackson Databind 2.9.8</p>" +
                "<p>Vulnerability: enableDefaultTyping() allows RCE</p>" +
                "<h3>Test Endpoint</h3>" +
                "<pre>POST /parse Body: {\"command\": [\"java.lang.Runtime\", \"exec\"]}</pre>" +
                "</body></html>";
        });
        
        System.out.println("Jackson Vuln Service started on port 8081");
    }
}
