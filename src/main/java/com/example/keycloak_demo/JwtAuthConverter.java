package com.example.keycloak_demo;

import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
public class JwtAuthConverter implements Converter<Jwt, AbstractAuthenticationToken> {

  private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter =
      new JwtGrantedAuthoritiesConverter();

  private final String principleAttribute = "preferred_username";

  @Override
  public AbstractAuthenticationToken convert(@NonNull Jwt source) {
    Collection<GrantedAuthority> authorities =
        Stream.concat(
                jwtGrantedAuthoritiesConverter.convert(source).stream(),
                extractResourceRoles(source).stream())
            .collect(Collectors.toSet());
    return new JwtAuthenticationToken(source, authorities, getPrincipleClaimName(source));
  }

  @SuppressWarnings("unchecked")
  private Collection<? extends GrantedAuthority> extractResourceRoles(Jwt source) {
    Map<String, Object> resourceAccess;
    Map<String, Object> resource;
    Collection<String> resourceRoles;
    if (null == source.getClaim("resource_access")) {
      return Set.of();
    }
    resourceAccess = source.getClaim("resource_access");
    if (null == resourceAccess.get("demo-rest-api")) {
      return Set.of();
    }

    resource = (Map<String, Object>) resourceAccess.get("demo-rest-api");
    resourceRoles = (Collection<String>) resource.get("roles");
    return resourceRoles.stream()
        .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
        .collect(Collectors.toSet());
  }

  private String getPrincipleClaimName(Jwt source) {
    String claimName = JwtClaimNames.SUB;
    if (null != principleAttribute) {
      claimName = principleAttribute;
    }
    return source.getClaim(claimName);
  }
}