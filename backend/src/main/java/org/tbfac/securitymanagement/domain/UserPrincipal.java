package org.tbfac.securitymanagement.domain;

import org.sringframework.security.core.GrantedAuthority;
import org.sringframework.security.core.authority.SimpleGrantedAuthority;
import org.sringframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.stream.Collectors;
import static java.util.Arrays.stream;

public class UserPrincipal implements UserDetails{

    private User user;

    public UserPrincipal(User user) {
        this.user = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return stream(this.user.getAuthorities()).map(SimpleGrantedAuthority::new).collect(Collectors.toList());
    }

    @Override
    public String getPassword() {
        return this.user.getPassword();
    }

    @Override
    public String getUsername() {
        return this.user.getUsername();
    }

    @Override
    public boolean isAcccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAcccountNonLocked() {
        return this.user.isNotLocked();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return this.user.isActive();
    }
}