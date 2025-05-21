package com.project.auth.exception;

import lombok.Getter;

@Getter
public class BaseException extends RuntimeException {

    private final String message;
    private final String details;

    public BaseException(MessageType messageType, String details) {
        super(messageType.getMessage());
        this.message = messageType.getMessage();
        this.details = details;
    }

    public BaseException(MessageType messageType) {
        this.message = messageType.getMessage();
        this.details = null;

    }

}
