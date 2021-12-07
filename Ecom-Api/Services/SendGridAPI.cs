using SendGrid;
using SendGrid.Helpers.Mail;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Ecom_Api.Services
{
    public class SendGridAPI
    {
        public static async Task<bool> Execute(
            string userEmail,
            string userName,
            string plainTextContent,
            string htmlContent,
            string subject)
        //function body
        {
            var apiKey = "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";
            var client = new SendGridClient(apiKey);
            var from = new EmailAddress("bobamagdy1333@gmail.com", "Heba Magdy");
            var to = new EmailAddress(userEmail, userName);
            var msg = MailHelper.CreateSingleEmail(from, to, subject, plainTextContent, htmlContent);
            var response = await client.SendEmailAsync(msg);
            return await Task.FromResult(true);
        }
        
    }
}
