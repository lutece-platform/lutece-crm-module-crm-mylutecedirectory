/*
 * Copyright (c) 2002-2012, Mairie de Paris
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice
 *     and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright notice
 *     and the following disclaimer in the documentation and/or other materials
 *     provided with the distribution.
 *
 *  3. Neither the name of 'Mairie de Paris' nor 'Lutece' nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * License 1.0
 */
package fr.paris.lutece.plugins.crm.modules.mylutecedirectory.service;

import fr.paris.lutece.plugins.crm.modules.mylutece.service.IMyLuteceUserService;
import fr.paris.lutece.plugins.mylutece.modules.directory.authentication.business.MyluteceDirectoryUser;
import fr.paris.lutece.plugins.mylutece.modules.directory.authentication.business.MyluteceDirectoryUserHome;
import fr.paris.lutece.plugins.mylutece.modules.directory.authentication.service.IMyluteceDirectoryService;
import fr.paris.lutece.plugins.mylutece.modules.directory.authentication.service.MyluteceDirectoryAnonymizationService;
import fr.paris.lutece.plugins.mylutece.modules.directory.authentication.service.MyluteceDirectoryPlugin;
import fr.paris.lutece.plugins.mylutece.modules.directory.authentication.service.parameter.IMyluteceDirectoryParameterService;
import fr.paris.lutece.plugins.mylutece.service.IAnonymizationService;
import fr.paris.lutece.plugins.mylutece.service.attribute.MyLuteceUserFieldService;
import fr.paris.lutece.plugins.mylutece.util.SecurityUtils;
import fr.paris.lutece.portal.service.admin.AdminAuthenticationService;
import fr.paris.lutece.portal.service.i18n.I18nService;
import fr.paris.lutece.portal.service.mail.MailService;
import fr.paris.lutece.portal.service.plugin.Plugin;
import fr.paris.lutece.portal.service.plugin.PluginService;
import fr.paris.lutece.portal.service.template.AppTemplateService;
import fr.paris.lutece.portal.service.util.AppPathService;
import fr.paris.lutece.portal.service.util.AppPropertiesService;
import fr.paris.lutece.util.html.HtmlTemplate;
import fr.paris.lutece.util.password.PasswordUtil;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import javax.inject.Inject;
import javax.inject.Named;

import javax.servlet.http.HttpServletRequest;


/**
 *
 * MyLuteceDirectoryUserService
 *
 */
public class MyLuteceDirectoryUserService implements IMyLuteceUserService<Collection<MyluteceDirectoryUser>>
{
    // PROPERTIES
    private static final String PROPERTY_NO_REPLY_EMAIL = "mail.noreply.email";
    private static final String PROPERTY_MESSAGE_EMAIL_SUBJECT = "module.mylutece.directory.forgot_password.email.subject";

    // MARKS
    private static final String MARK_NEW_PASSWORD = "new_password";
    private static final String MARK_LOGIN_URL = "login_url";

    // TEMPLATES
    private static final String TEMPLATE_EMAIL_FORGOT_PASSWORD = "admin/plugins/mylutece/modules/directory/email_forgot_password.html";
    @Inject
    private IMyluteceDirectoryService _myluteceDirectoryService;
    @Inject
    private IMyluteceDirectoryParameterService _parameterService;
    @Inject
    @Named( MyluteceDirectoryAnonymizationService.BEAN_SERVICE )
    private IAnonymizationService _anonymizationService;

    /**
     * {@inheritDoc}
     */
    @Override
    public Collection<MyluteceDirectoryUser> getMyLuteceUserByUserGuid( String strUserGuid )
    {
        return _myluteceDirectoryService.getMyluteceDirectoryUsersForLogin( strUserGuid,
            PluginService.getPlugin( MyluteceDirectoryPlugin.PLUGIN_NAME ) );
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void doRemoveMyLuteceUser( Collection<MyluteceDirectoryUser> listMyLuteceUsers, HttpServletRequest request,
        Locale locale )
    {
        if ( ( listMyLuteceUsers != null ) && !listMyLuteceUsers.isEmpty(  ) )
        {
            for ( MyluteceDirectoryUser user : listMyLuteceUsers )
            {
                _myluteceDirectoryService.doRemoveMyluteceDirectoryUser( user,
                    PluginService.getPlugin( MyluteceDirectoryPlugin.PLUGIN_NAME ), true );
                MyLuteceUserFieldService.doRemoveUserFields( user.getIdRecord(  ), request, locale );
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void doAnonymizeMyLuteceUser( Collection<MyluteceDirectoryUser> listMyLuteceUsers,
        HttpServletRequest request, Locale locale )
    {
        if ( ( listMyLuteceUsers != null ) && !listMyLuteceUsers.isEmpty(  ) )
        {
            for ( MyluteceDirectoryUser user : listMyLuteceUsers )
            {
                _anonymizationService.anonymizeUser( user.getIdRecord(  ), locale );
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void doReinitPassword( Collection<MyluteceDirectoryUser> listMyLuteceUsers, HttpServletRequest request,
        Locale locale )
    {
        if ( ( listMyLuteceUsers != null ) && !listMyLuteceUsers.isEmpty(  ) )
        {
            Plugin plugin = PluginService.getPlugin( MyluteceDirectoryPlugin.PLUGIN_NAME );

            for ( MyluteceDirectoryUser user : listMyLuteceUsers )
            {
                // make password
                String strPassword = PasswordUtil.makePassword(  );

                MyluteceDirectoryUser userStored = _myluteceDirectoryService.getMyluteceDirectoryUser( user.getIdRecord(  ),
                        plugin );
                userStored.setPasswordMaxValidDate( SecurityUtils.getPasswordMaxValidDate( _parameterService, plugin ) );
                strPassword = SecurityUtils.buildPassword( _parameterService, plugin, strPassword );
                MyluteceDirectoryUserHome.updatePassword( userStored, strPassword, plugin );

                List<String> listEmails = _myluteceDirectoryService.getListEmails( userStored, plugin, locale );

                if ( ( listEmails != null ) && !listEmails.isEmpty(  ) )
                {
                    //send password by e-mail
                    String strSenderEmail = AppPropertiesService.getProperty( PROPERTY_NO_REPLY_EMAIL );
                    String strEmailSubject = I18nService.getLocalizedString( PROPERTY_MESSAGE_EMAIL_SUBJECT, locale );
                    Map<String, Object> model = new HashMap<String, Object>(  );
                    model.put( MARK_NEW_PASSWORD, strPassword );
                    model.put( MARK_LOGIN_URL,
                        AppPathService.getBaseUrl( request ) +
                        AdminAuthenticationService.getInstance(  ).getLoginPageUrl(  ) );

                    HtmlTemplate template = AppTemplateService.getTemplate( TEMPLATE_EMAIL_FORGOT_PASSWORD, locale,
                            model );

                    for ( String email : listEmails )
                    {
                        MailService.sendMailHtml( email, strSenderEmail, strSenderEmail, strEmailSubject,
                            template.getHtml(  ) );
                    }
                }
            }
        }
    }
}
