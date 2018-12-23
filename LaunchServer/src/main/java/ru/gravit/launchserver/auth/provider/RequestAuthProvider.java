package ru.gravit.launchserver.auth.provider;

import ru.gravit.launchserver.auth.ClientPermissions;
import ru.gravit.utils.helper.CommonHelper;
import ru.gravit.utils.helper.IOHelper;
import ru.gravit.utils.helper.SecurityHelper;

import java.io.IOException;
import java.net.URL;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class RequestAuthProvider extends AuthProvider {
    private String url;
    private Pattern response;
    private boolean usePermission;

    @Override
    public AuthProviderResult auth(String login, String password, String ip) throws IOException {
        String currentResponse = IOHelper.request(new URL(getFormattedURL(login, password, ip)));

        // Match username
        Matcher matcher = response.matcher(currentResponse);
        return matcher.matches() && matcher.groupCount() >= 1 ?
                new AuthProviderResult(matcher.group("username"), SecurityHelper.randomStringToken(), usePermission ? new ClientPermissions(Long.getLong(matcher.group("permission"))) : new ClientPermissions()) :
                authError(currentResponse);
    }

    @Override
    public void close() {
        // Do nothing
    }

    private String getFormattedURL(String login, String password, String ip) {
        return CommonHelper.replace(url, "login", IOHelper.urlEncode(login), "password", IOHelper.urlEncode(password), "ip", IOHelper.urlEncode(ip));
    }
}
