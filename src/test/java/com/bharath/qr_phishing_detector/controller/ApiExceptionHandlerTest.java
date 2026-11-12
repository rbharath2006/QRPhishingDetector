
package com.bharath.qr_phishing_detector.controller;
import static org.mockito.Mockito.verifyNoInteractions;
import com.bharath.qr_phishing_detector.detection.RedirectAnalysisService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.mockito.Mockito.mock;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.standaloneSetup;
import static org.mockito.Mockito.when;
class ApiExceptionHandlerTest {

    private MockMvc mockMvc;
    private RedirectAnalysisService service;

    @BeforeEach
    void setUp() {
        service = mock(RedirectAnalysisService.class);

        RedirectAnalysisController controller =
                new RedirectAnalysisController(service);

        mockMvc = standaloneSetup(controller)
                .setControllerAdvice(new ApiExceptionHandler())
                .build();
    }

    @Test
    void malformedJsonReturnsBadRequest() throws Exception {
        mockMvc.perform(
                        post("/api/v1/redirect-analysis")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"url\":")
                )
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(
                        "Request body is missing or contains invalid JSON."
                ));
    }

    @Test
    void unexpectedExceptionReturnsGenericError() throws Exception {
        when(service.resolve("https://bit.ly/example123"))
                .thenThrow(new IllegalStateException(
                        "Sensitive internal diagnostic"
                ));

        mockMvc.perform(
                        post("/api/v1/redirect-analysis")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"url\":\"https://bit.ly/example123\"}")
                )
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.error").value(
                        "An unexpected server error occurred."
                ))
                .andExpect(content().string(
                        org.hamcrest.Matchers.not(
                                org.hamcrest.Matchers.containsString(
                                        "Sensitive internal diagnostic"
                                )
                        )
                ));
    }



    @Test
    void blankUrlReturnsBadRequestWithoutCallingService() throws Exception {
        mockMvc.perform(
                        post("/api/v1/redirect-analysis")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"url\":\"   \"}")
                )
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(
                        "Provide a URL between 1 and 2048 characters."
                ));

        verifyNoInteractions(service);
    }

    @Test
    void oversizedUrlReturnsBadRequestWithoutCallingService()
            throws Exception {
        String oversizedUrl = "a".repeat(2049);
        String requestBody = "{\"url\":\"" + oversizedUrl + "\"}";

        mockMvc.perform(
                        post("/api/v1/redirect-analysis")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(requestBody)
                )
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(
                        "Provide a URL between 1 and 2048 characters."
                ));

        verifyNoInteractions(service);
    }

}
