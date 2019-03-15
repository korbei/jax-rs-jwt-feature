package com.korbei.rs.jwt;

import java.util.Calendar;
import java.util.Date;

public class TestUtil {

    public static String generateToken() {
        return generateToken(Calendar.MINUTE, 1);
    }

    public static String generateInvalidToken() {
        return generateToken(Calendar.MINUTE, -1);
    }

    private static String generateToken(int calendarField, int amount) {
        final Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.add(calendarField, amount);

        final String[] roles = {"admin", "user"};
        return Token.create()
                .withSubject("korbei")
                .withRoles(roles)
                .withExpiresAt(calendar.getTime())
                .withIssuedAt(new Date())
                .sign();
    }
}
