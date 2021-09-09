package org.ada.school.utils;


public interface Constants
{
    String COOKIE_NAME = "ada-JWT";

    String CLAIMS_ROLES_KEY = "ada_roles";

    int TOKEN_DURATION_MINUTES = 1440;
    int TOKEN_DURATION_TEN_MINUTES = 10;

    String ADMIN_ROLE = "ADMIN";
    String USER_ROLE = "USER";
}