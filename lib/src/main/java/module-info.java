module com.auth0.jwt {
    requires com.fasterxml.jackson.databind;
    requires knca.provider.jce.kalkan;

    exports com.auth0.jwt;
    exports com.auth0.jwt.algorithms;
    exports com.auth0.jwt.exceptions;
    exports com.auth0.jwt.interfaces;
}
