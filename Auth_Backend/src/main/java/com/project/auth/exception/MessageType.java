package com.project.auth.exception;

public enum MessageType {
    NO_RECORD_EXIST("1001", "There is no such thing!"),
    GENERAL_EXCEPTION("1002", "A GENERAL ERROR HAS OCCURRED!"),
    INVALID_TOKEN("1003", "Invalid JWT token"),
    EXPIRED_TOKEN("1004", "Token expired."),
    VALIDATION_ERROR("1005", "Validation Error");

    private final String code;
    private final String message;

    MessageType(String code, String message) {
        this.code = code;
        this.message = message;
    }

    public String getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }
}