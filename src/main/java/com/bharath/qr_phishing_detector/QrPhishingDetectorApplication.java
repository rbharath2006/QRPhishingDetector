package com.bharath.qr_phishing_detector;

import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
@EnableScheduling
@SpringBootApplication
public class QrPhishingDetectorApplication {

	public static void main(String[] args) {
		SpringApplication.run(QrPhishingDetectorApplication.class, args);
	}

}
