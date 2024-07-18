# Broken Authentication

Broken authentication includes a bunch of authentication loopholes that an attacker exploits as vulnerabilities. An attacker can then use it to authenticate on behalf of a legitimate user of your app. This lets an attacker steal a user's credentials and access private resources for that particular user.

Authentication is handled mostly on the server side. However, there are a few techniques you can implement on the client side to prevent broken authentication. Let's look at these techniques in detail.

## Map Session-ID to the Device ID and IP Address/Location

Session-Id is a unique UUID that you create to map a session against a user in your database. For instance, if a user is authenticated in your app, your back-end server would send back a session ID. When the user logs out, this session ID is cleared.

![How session id works](https://images.ctfassets.net/nx13ojx82pll/191Q5tdmW6DxC1KoGbNcgw/7ea3f5de581b1060411de1715ca133e0/react-broken-authentication-guide-2.png?w=1600&h=900&q=80&fm=webp)

However, just mapping a session ID to a user is not sufficient. Think about the case where an attacker is trying to authenticate in disguise as a legitimate user from their own device. In this case, the device ID will be able to tell you if a session was triggered from a different device.

## The useDeviceId Hook in React

The device ID is something you'll need to retrieve from the client side. So how do we do that? We can use a library called FingerprintJS in our React app to do so. Here I have created a React hook that gets the device ID from the FingerprintJS library and returns it back.
You'll need a Fingerprint browser token, an API secret key equivalent, for the above to work. I got mine by creating an account on FingerprintJS and grabbing that key from your [dashboard](https://dashboard.fingerprintjs.com/).

Next, we also need the location data of the user. We can use the Geolocation API to retrieve the location information and IP address of the user. Note that there may be better services you could use to get more accurate and appropriate location data. However, the underlying principle is the same.

## The useLocation Hook in React

Here's another hook you can use in your React app that gives you the user's location information
Now let's quickly use these hooks to see if they're working. Inside App.js, I have simply invoked these hooks and displayed the information inside the template

You can integrate these hooks with your client-side authentication. Every time a user attempts to log in or sign up, you can send this information to the server. The server can then validate the device ID and location information to send back a flag that indicates if the session is from a different location, different device, etc.

![Mapping the session id against the user's location and device id.](https://images.ctfassets.net/nx13ojx82pll/4lAXzzwb9HiKfS12yJTVaz/17e4141367d67de4809bebf88f41bd9e/react-broken-authentication-guide-4.png?w=1600&h=900&q=80&fm=webp)

You can then alert the user accordingly or automatically sign them out by calling your Logout API.

## Auto Sign Out for Idle User

Session timeouts for idle users are more important than you think. Most financial websites implement them for mere security purposes. There are three steps to implement an automatic session timeout for idle users of your app.

First, you need an idle session TTL. This means how long you need to check for an idle user before you can trigger session termination. Next, you need to detect user activity to check if the user is active or idle. Finally, you need to call your Logout API when your React app detects that your user is idle for the specified time.

![How to implement auto signout for an idle user.](https://images.ctfassets.net/nx13ojx82pll/6lpaGP5ZDiCiLqCQli5nOA/b430a5167547d7995dc8f49d7a86dcd7/react-broken-authentication-guide-6.png?w=1600&h=900&q=80&fm=webp)

Let's assume you get an idle session timeout from your server. The remaining two steps need to be performed on the client side. We can easily detect if a user is active or idle in React using a package called react-idle-timer.

## The useIdle Hook in React

You'll need to install react-idle-timer first by running:

```console
npm install react-idle-timer --save
```

We'll abstract this logic into a separate hook called useIdle.js that looks like this

## Broken Authentication Due to Poor Session Management

Session management refers to how you're handling the session of the user. It includes the following:

- How you are generating session IDs for your users on each session
- Where you store the session ID on the front end
- Where you store JWT/authentication/refresh tokens on the front end
- How you handle session timeouts for your application.

All these factors help you validate if your session management is poor enough to let attackers enter your application as legitimate users.
If you're not taking care of how you're creating and storing session ids, attackers can make authentication requests on behalf of a user.

For instance, if an attacker gets hold of a user's session ID, they will be able to change passwords or retrieve personal information for that user.

## Implement Safe Session Management

Most session management techniques cater to the server side. This is because the client only handles how to store the session ID. However, you need to be careful how and where you store your session ID in your React app.

![Avoid using query strings for storing information related to the session.](https://images.ctfassets.net/nx13ojx82pll/2tUpjOQWckUZ1y1F7zbuRl/618c79fddc4a50aeb93a94ba08e77254/react-broken-authentication-guide-7.png?w=1600&h=900&q=80&fm=webp)

A lot of times developers store session-id in front-end URLs, making it clearly visible to users as well as attackers. Instead, you could store the session-id inside browser storage and use it via a custom React hook in whichever component or page of your application you need it.

## The useSession Hook in React

Here's a simple implementation of the useSession hook in React. It syncs the session ID in the local storage with its own state. It returns back this session ID so you can simply call this hook to retrieve the session ID from anywhere in your React application.

So now whenever you need to use session ID on a particular page, you can grab it from this hook. Thus, you won't need to pass it as query parameters in your React app's routes.

# XSS (cross-site scripting)

JavaScript lies at the heart of the client-side of any application. This is because your application's front end roughly amounts to some JavaScript code running on your browser.

To illustrate this, let's take a simple example of an online transaction. When you carry out a transaction on a website, it runs some JavaScript to grab your credentials from the input fields and process them. However, the developers can easily run some additional JavaScript to do something detrimental with that information.

That's precisely what XSS is. An attacker can exploit your application's vulnerability to inject some malicious script into your user's browser, carrying out an XSS attack. Now that you know what an XSS attack is, let's understand how it can happen with an example.

## How Can an XSS Attack Happen?

One of the most common types of XSS attacks is a DOM-based XSS attack. When you mutate DOM directly, it becomes easy for an attacker to inject it with data containing malicious JavaScript.
Consider the following HTML code. It simply renders some basic markup with an empty div element.

```html
<html>
  <body>
    <div id="validation"></div>
    <input placeholder="Enter your referral code below" />
    <button>Submit</button>
  </body>
</html>
```

The above code renders an input element on the page with a submit button. On pressing the submit button, you fire a function. Inside the function, you evaluate what the user has entered. You then provide a feedback message to the user based on the result inside the empty div element.

```js
const validationElement = document.getElementById("validation");
const validationMessage = `Oops! This seems like an invalid referral code.`;
validationElement.append(validationMessage);
```

Using the append method, you render a message inside your empty div element. However, this exposes a vulnerability in your application. Consider the following JavaScript code.

```js
Oops! This seems like an invalid referral code.
<script>
  ...
  alert('Congrats! You've won a prize');
  ...
</script>
```

The attacker basically renders the validation message along with a malicious script. This was possible because the application was modifying DOM directly using the append() method on the div. Inside the script, the attacker can write code that steals your confidential and sensitive information. On similar grounds, if you use innerHTML to mutate DOM directly, you are exposing your application to a potential XSS attack.

Thus, an XSS attack can be an alarming sight for your users. However, front-end frameworks have come a long way and provide some protection against such attacks out of the box. Let's look at how React handles these situations for you and how far it secures your application against an XSS attack.

## Is React XSS Foolproof?

Luckily, React does a few things under the hood to safeguard your application against XSS attacks. Let's rewrite the code in the previous section in React.

Just like before, I have an input element with a button that fires the validateMessage function. I have created a state validationMessage that I set inside the validateMessage function using a setTimeout. Finally, I output the validationMessage inside an empty div element using JSX.

```html
<div>{validationMessage}</div>
```

React outputs elements and data inside them using auto escaping. It interprets everything inside validationMessage as a string and does not render any additional HTML elements. This means that if validationMessage was somehow infiltrated by an attacker with some script tags, React would simply ignore it and render it as a string.

```js
const validateMessage = async () => {
  setTimeout(() => {
    setValidationMessage(`Invalid referral code, <script></script,.>`);
  }, 1000);
};
```

If you check now, the script tags get rendered as strings instead of a DOM element.

Now, any JavaScript enclosed by the script tags will not be executed. Thus, the above behavior protects your application from an attacker trying to execute a DOM-based XSS attack.
But does that mean your React application is safe from all kinds of XSS attacks? We only considered the use case of outputting an element or a string using JSX. What if we actually need to render HTML elements directly on the DOM from inside the JSX?

## Render HTML Elements Dynamically in React

The most common use case where you'd want to render HTML elements directly is a blogging application. In typical blogging applications, you receive your blogs as a combination of HTML elements. These elements wrap your blog's content, preserving its formatting.

Let's say you have a small React component that gets a blog from the server and renders it on the DOM.

```js
import "./App.css";
function App() {
  const blog = `
   <h3>This is a blog title </h3>
   <p>This is some blog text. There could be <b>bold</b> elements as well as <i>italic</i> elements here! <p>
  `;
  return (
    <div className="App">
      <div>{blog}</div>
    </div>
  );
}

export default App;
```

Inside the component, I have a blog variable that stores your blog's content wrapped in proper HTML elements. If you directly output the blog variable inside your JSX, it would be interpreted as a string.

![Rendering a blog using JSX.](https://images.ctfassets.net/nx13ojx82pll/6Sj0KuXV3xZiyAYahaEgIN/c0b334da70638954354e89608ee0257a/react-xss-guide-examples-and-prevention-picture-3.png?w=1262&h=178&q=80&fm=webp)

While that safeguards your application against a DOM-based XSS attack, it ruins the experience for your users. Therefore, you need to render your blog as a markup instead of rendering it as a string. This will render your content along with its dedicated HTML tags.

React allows you to do that using a prop called dangerouslySetInnerHTML. You can pass this prop to any generic container element. It takes in an object with a key \_html whose value is the HTML markup you wish to render inside the container.

```html
<div className="App">
  <div dangerouslySetInnerHTML="{{__html:blog}}"></div>
</div>
```

If you check back now, you should see your blog with its intended formatting.

![Rendering formatted blog using dangerouslySetInnerHTML](https://images.ctfassets.net/nx13ojx82pll/4xfecPWZ7qdMK4AcFkFmn5/b39d51b4c11d64a2f30fa1c6704a9219/react-xss-guide-examples-and-prevention-picture-4.png?w=1284&h=234&q=80&fm=webp)

All HTML elements contained by the blog variable are properly rendered on the DOM. However, this puts us back at square one! We again have an XSS vulnerability in our application, and the attacker could inject some malicious scripts inside the blog variable. In fact, the dangerouslySetInnerHTML prop intentionally has the word "dangerous" in it to remind you that you should be cautious while using it.

## Sanitize Data in React

In order to protect your application from a DOM-based XSS attack, you must sanitize data that contains HTML elements before rendering it on the DOM. There are a number of libraries out there that you can use. One such library is DOMPurify. Let's see how we can use it in our React application.

Let's first install DOMPurify inside our React application by running the following command:

```console
npm i dompurify
```

To use it, import DOMPurify from the library at the top as shown:

```js
import DOMPurify from "dompurify";
```

Let's create a new variable, sanitizedBlog, that contains the sanitized version of our blog.

```js
const sanitizedBlog = DOMPurify.sanitize(blog);
```

Finally, we can now use sanitizedBlog instead of blog inside the dangerouslySetInnerHTML prop as shown:

```html
<div className="App">
  <div dangerouslySetInnerHTML="{{__html:" sanitizedBlog}}></div>
</div>
```

Everything should still work the same, but your sanitizedBlog is now protected against any malicious XSS injections.

## Escape Hatches in React Can Cause an XSS Attack

A lot of times, you want to get a reference to a DOM element in your React application. React provides you with findDOMNode and createRef as escape hatches. These methods give a direct reference to the DOM elements.

```js
import "./App.css";
import { useEffect, createRef } from "react";

function App() {
  const divRef = createRef();
  const data = "lorem ipsum just some random text";

  useEffect(() => {
    divRef.current.innerHTML = "After rendering, this will display";
  }, []);

  return (
    <div className="App">
      <div className="container" ref={divRef}>
        {data}
      </div>
    </div>
  );
}

export default App;
```

I have a simple div with the ref divRef. When the component's DOM loads, I change the content inside this div using the innerHTML property on its ref. An attacker can easily inject some malicious script by overriding the innerHTML of the div inside the useEffect.

The trick here is simple. Don't use innerHTML to mutate DOM at all! This is yet again a similar situation where you're modifying DOM directly. If you are using refs to add some content inside your HTML elements, use innerText instead.

```js
useEffect(() => {
  divRef.current.innerText = myName;
}, [myName]);
```

Now, even if the attacker is able to inject some script tags through divRef, it will be rendered as a string in your application. This kind of pattern is rare, and you should always avoid mutating DOM directly using refs.

# CSRF (Cross Site Request Forgery)

Do you ignore your spam emails? To be honest, they could be more dangerous than you think. Be cautious when visiting a website flooded with advertisements and clickbait. An attacker behind the screen may trick you into doing something malicious, such as deleting your account on a website, transferring funds illegitimately, and so on. These are all possible outcomes of a CSRF attack.

Other names for these attacks are ["one-click attacks" or "session riding"](<https://www.techopedia.com/definition/172/cross-site-request-forgery-csrf#:~:text=Cross%2Dsite%20request%20forgery%20(CSRF)%20is%20a%20type%20of,from%20a%20trusted%20website%20user.&text=This%20term%20is%20also%20known,or%20a%20one%2Dclick%20attack.>). CSRF attacks aren't common these days. But understanding how they work is vital if you want to build secure services and web applications. And even in the past few years, CSRF attacks have gotten well-known companies into trouble.

## A Bird's-Eye View of CSRF

### Cross-Site Request

The "cross-site request" part simply means a request sent from site A that was supposed to be sent from site B. This doesn't sound that bad, right? Well, only if I authorized that request.

For instance, it's fine if I delete my Firebase account from my Google account. However, if I were to do the same using my random XYZ account, chances are that my Firebase account is compromised.

The next question is: Why would I do that? Why would I want to delete my Firebase account using some other random website that has no correlation with it?

There could be a couple of use cases that cater to this scenario. For instance, I might authorize my Google Cloud account to delete my Firebase account. Similarly, I might authorize my Facebook account to delete my Instagram account. However, if I visit a random website that wipes out my Instagram account, I'd be concerned about the security of my social media handles.

### Forgery

The other part of the term, "forgery," means forcibly and illegally carrying out an action you aren't authorized to do.

So if you put two and two together, CSRF or cross-site request forgery means an unknown application forges a request to your server. But how does an attacker send a request on your behalf?

## A CSRF Attack in Action

Now that you have a good idea of what CSRF really means, let's look at how an attacker might execute a CSRF attack on your application.

For the purpose of this example, let's say you've got a web application with a ReactJS front end that interacts with the back end server.

## Application Demo

Let's say your application has a simple home page and a profile page. The home page of your application is visible to anyone on the web. For brevity, the following application shows a simple page that lists a couple of users.

![Home Page Demo.](https://images.ctfassets.net/nx13ojx82pll/2Epkfe1EfdyR3f4thXhOfz/f1345a4f5411dc1993fe872d42e71755/react-csrf-protection-guide-examples-and-how-to-enable-it-picture-2.png?w=1802&h=790&q=80&fm=webp)

However, in order to access the profile page, a user must be authenticated on the app. Inside the profile page, there's a small button that enables the user to delete their account. Let's say the profile page looks like this.

![Profile Page Demo.](https://images.ctfassets.net/nx13ojx82pll/6AxQqCNkfD02WospUr7FOY/21c07a3e60d3f7159f33f89c6a0d15a0/react-csrf-protection-guide-examples-and-how-to-enable-it-picture-3.png?w=1796&h=694&q=80&fm=webp)

## Authentication Flow

Let's say your user tries to log in to your application using a login form. The user fills in this form to validate her credentials from the server. Like most typical authentication flows, the server sends a cookie that's used to manage the session of the user. This cookie is stored in the browser and is sent back with every request to validate the authenticity of the user.

## The Vulnerability

Let's say a user wants to delete her account on your site. To do this, she must click a Delete button. However, only a user who has signed in to the application can perform this action.

When the user presses Delete, the client sends a delete request to your server. The server processes this request and carries out a delete operation on your database. Your delete request would look somewhat like this:

![CSRF Attack Request.](https://images.ctfassets.net/nx13ojx82pll/3Da3UL7JcGJWuNGk3jRtxN/a34218e2b9889f2735c0b80513ebcdf3/react-csrf-protection-guide-examples-and-how-to-enable-it-picture-4.png?w=1800&h=574&q=80&fm=webp)

To validate the authenticity of the delete request, the user's browser stores the session token as a cookie. However, this leaves a CSRF vulnerability in your application. An attacker can send a delete request to your server with the cookie present in the browser. All they need you to do is open a link with a hidden form that triggers this delete request in the background. Let's see how this works.

## The Attack

In this example, the triggering point for the attack is opening a URL. The attacker generates a URL that points to another web application. The attacker then uses social engineering to open that URL in the user's browser.

As soon as the application loads, it gets access to the session cookie stored in your browser. And that's it! The attack could be triggered under the hood, in the background, while the malicious link loads.

## Aftermaths of the Attack

Your user would have no idea that she was under a CSRF attack! Eventually, though, she'd question your application's credibility and might not want to use your app again.

The scale of this attack may be huge, which makes it even worse for you if the attacks delete the accounts of a large number of users. This makes your product look weak and eventually affects your business. You may lose a ton of users—and if the word gets out, you may lose some potential users as well.

Hence, it's important to safeguard your system from a CSRF attack. Let's see how you can do so.

## CSRF Protection: Myth Busters

To understand how you can protect your application from a CSRF attack, you must first understand the solutions that aren't reliable. These solutions seem easy, but an attacker can easily bypass them. And your application might still be vulnerable to a CSRF attack.

Let's have a quick glimpse at these:

### Using Web Storage Instead of Cookies

Do you think you can store the authentication tokens inside the browser's local or session storage instead of cookies to solve this problem? Think again. The attacker can access any data you store on your browser's local storage by running the following line of code:

```js
const token = localStorage.getItem("token");
```

And once the attacker gets access to your session token, you're back to square one! Sure, this might add another blocking step for the attacker, but it definitely isn't a reliable solution.

### Using a POST Request

If you refactor your server endpoints and make every endpoint a POST request, you're still not completely safe from a CSRF attack. In the previous section, I illustrated an example of a delete request to delete the user's account. This could have been a GET request as well.

You might think that using a POST request will add another pain point for the attacker to figure out the request body and parameters. However, it's still merely another barrier and not a foolproof solution.

## CSRF Protection: The Reliable Solution

Let's go through the steps you can follow to protect your application against a CSRF attack.

### Using CORS on the Server

CORS stands for cross-origin resource sharing. It's a protocol that allows your client to send requests and accept responses from a server that has a different origin. Normally, the browser uses an SOP or same-origin policy to ensure that your server only listens to requests from clients of the same origin.

However, sometimes you want to expose some public API endpoints of your server so different clients can access it. Or maybe you simply wish to host your server and client on different domains. In these scenarios, the browser's SOP doesn't allow your server to communicate with your client as a security measure.

CORS lets you work around that problem so your server can communicate with clients of different origins. This is possible if your server has the following line of code inside the request handlers or middleware.

```js
app.get('/delete',(req,res)=>{
 res.set('Access-Control-Allow-Origin', '*');
 ...

})
// Instead of accepting requests from any client, limit your server to accept requests from only your client. For instance, if your client is running csrfprotection-client.com and the server is running csrfprotection-server.com, replace the above lines with the following ones.
app.get('/delete',(req,res)=>{
   res.set('Access-Control-Allow-Origin', 'csrfprotection-client.com');
   ...
})
```

You can learn more about CORS [here](https://github.com/ashwin-magalu/react-vulnerabilities-fixes/tree/master?tab=readme-ov-file#cors)

### Using CSRF Tokens

CSRF tokens, also called anti-CSRF tokens, let your server communicate to the client before an authenticated request is made that may be tampered with. Let's go back to the previous example, where an attacker sent a delete request from a client from your browser.

Let's say you have a NodeJS and Express back end that interacts with your React client. You can install a library called csurf that's used to generate CSRF tokens, and you can send them to your client through an endpoint.

```console
npm i csurf
```

Now you need to add the following endpoint.

```js
const csrfProtection = csrf({
  cookie: true,
});
app.use(csrfProtection);
app.get("/getCSRFToken", (req, res) => {
  res.json({ CSRFToken: req.CSRFToken() });
});
```

The above is a simple GET endpoint that returns a CSRF token.You can send a GET request to that endpoint to retrieve the CSRF token. I'm using Axios in this example, but you can also use Fetch API to send valid headers with the X-CSRF-Token attached to the request.

```js
const getCSRFToken = async () => {
  const response = await axios.get("/getCSRFToken");
  axios.defaults.headers.post["X-CSRF-Token"] = response.data.CSRFToken;
};
```

Let's say your minimal profile page component in React looks like this.

```js
import { useState, useEffect } from "react";

export default function Profile() {
  const [user, setUser] = useState();
  const getUsers = async () => {
    const response = await fetch("https://randomuser.me/api/");
    const data = await response.json();
    console.log(data.results[0]);
    setUser(data.results[0]);
  };
  useEffect(() => {
    getUsers();
  }, []);
  const handleDelete = () => {};
  return (
    <div className="users">
      <div className="user">
        <div className="user__img">
          <img src={user.picture.thumbnail} />
        </div>
        <div className="user__name">
          {user.name.first + " " + user.name.last}
        </div>
        <div className="delete" onClick={handleDelete}>
          DELETE
        </div>
      </div>
    </div>
  );
}
```

You can then call the getCSRFToken function inside the useEffect as shown:

```js
useEffect(() => {
  getUsers();
  getCSRFToken();
}, []);
```

That's it! This CSRF token is sent alongside every request, and it generates every time your profile page loads.

However, you need to make sure you don't have any XSS vulnerabilities in your application that can leak these tokens to the attacker.

# XML External Entities

XML, or Extensible Markup Language, is a markup language and file format for storing, transmitting, and reconstructing arbitrary data. In addition, this language is used in the programming world to define rules for encoding documents in a format that is both human-readable and machine-readable.

Alright then, but how can a file structure become a threat to your application?

By default, XML processing tools allow the specification of an external entity, a URI, retrieved and processed during the XML file parsing. In the process of file parsing, XML processing code can retrieve these external entities without validation. Attackers can circumvent your security measures by requesting and embedding the content on the specified external entity inside the XML document. This is essentially an open back door. An attacker could leverage this property as an avenue to retrieve any resource.

In a nutshell, an XML External Entities attack, or XXE injection, is an attack that takes advantage of XML parsing vulnerabilities. It targets systems that use XML parsing functionalities that face the user and allow an attacker to access files and resources on the server. XXE injection attacks can include disclosing local files containing sensitive data, such as passwords or private user data using file: schemes or relative paths in the system identifier.

In essence, this vulnerability could render your server insecure given enough persistence and time.

## Looking for XML External Entities

The following example is a bare-bones XML document containing an item XML element.

```html
<item id="1">
  <title>Toilet Paper</title>
</item>
```

Great, but where's the external entity?

You would represent an external entity by using a system identifier within a DOCTYPE header.

```html
<!ENTITY xxe SYSTEM "https://www.google.com" >]>
```

The purpose of this header is to add more properties to the XML data structure. To illustrate this further, the code below contains an external XML entity that would try to compromise a potentially perpetual file.

```html
<!ENTITY xxe SYSTEM "file:///gkr/rand" >]>
<item id="1">
<title>&xxe;</title>
</item>
```

This attack would result in a denial of service (DoS) attack and bring your server to its knees. Yikes!

As we've mentioned in other articles, these entities can access local or remote content, so you need to protect the sensitive files on the server.

By not doing so, you could potentially provide an attacker with a way to gain control of your website. Game over. By no means is this a thorough explanation of XML External Entities or XXE attacks. Exploring all the complexities of this vulnerability is beyond the scope of this article.

## A Simple Way to Mitigate React XML External Entities

How can you fix this mess?
Thankfully, most of the work has already been done for you.

As a quick refresher, and for the sake of brevity, I'll briefly refer to a previous article on the recommended approach to take.

Generally, as long as you are not intentionally trying to open a window for the vulnerability and consider that you need the functionality of loading user-provided XML files, you don't have to worry much about this issue.

Let's illustrate.

As we have mentioned, if an application has an endpoint that parses XML files, an attacker could send a specially crafted payload to the server and obtain sensitive files. The files the attacker can get depend heavily on how you set up your system and how you implement user permissions.

So, to prevent this situation from playing out, first, don't use libraries that support entity replacement.

Luckily, JavaScript has no popular XML parsing libraries with such a problem.

Generally, you have done most of the work as long as you keep your libraries updated. Your application is likely implementing react-xml-parser, which already comes with protections against this vulnerability. Additionally, for most libraries, external entities are disabled by default.

A straightforward example of a protected implementation on React would be the following:

```js
var XMLParser = require("react-xml-parser");
var xml = new XMLParser().parseFromString(xml_text);
console.log(xml);
```

Additionally, if your platform does require the use of external entities, you can safelist known external entities to minimize the potential for exploits.

## Other Strategies

Here are some other strategies you can take to mitigate XXE Injection attacks:

Use simpler data formats like JSON and avoid serialization of sensitive data.

Patch or upgrade all XML processing code and libraries in your application.

Verify that XML file upload validates incoming XML using XSD validation.

Update SOAP to SOAP 1.2 or higher.

Use SAST tools to help detect XXE in source code.

Finally, as a rule of thumb, do not implement the processing of XML unless it's an application requirement. There are numerous ways to offer similar features without opening your application to threats.

The most practical mitigation approach to vulnerabilities is to not be open to them in the first place.

# Command Injection

Command injection is considered to be one of the five most dangerous injection attacks. It's equivalent to a malicious attacker using your system themselves. Imagine the damage an attacker will be able to do if they were to get access to your entire system.

As a developer, you've used the command line terminal to do literally everything—creating folders, reading files, or even deleting them. Command injection transfers all this power to the attacker. But how does that really happen? What all can an attacker do?

## What Is an Injection Attack?

Most injection attacks follow a similar pattern across all their variants. In its most primitive step, an injection attack finds a vulnerability in the application. This vulnerability provides a gateway to get unauthorized access to server files, system OS, etc. The attacker then injects some code through this gateway to steal data, modify system files, or execute shell commands.

Based on the type of injection attack, the code is injected in different ways. If it's a client-side vulnerability, the easiest way for an attacker to inject code is through JavaScript. In this case, the attacker injects a script that runs on the user's browser.

On the other hand, if it's the server, the attacker could inject some shell commands. We know how powerful shell commands are. They can interact directly with your system-level APIs.

## What Exactly Is a Command Injection Attack?

A command injection attack is more lethal because it gives the attacker more privileges than a regular injection attack. Earlier, I talked about how attackers can inject a malicious script on the client side. However, the script can only execute some JavaScript. The extent to which it can hamper your application is largely influenced by what JavaScript can do.

In other words, injecting code or a script often becomes limited to the language. However, that's not the case with command injection.

This gives the attacker complete control over your system. Consequently, the attacker can read your environment secrets and other configurational files. Not only this, but the attacker can also modify or delete other files on your system.

## Example of a Command Injection Attack

Typical command injection attacks happen directly on the server, but they may also be triggered from the client side. Let's assume you have a React app on the front end and a NodeJS server on the back end.

### Create a Back-End Server

To set up the latter, run the following command:

```console
cd command-injection-server && npm init -y && npm i express
```

Let's assume that your back end receives the name of a text file stored locally on your server. This text file stores the version of your server. You need to validate if your back end and front end are running on the same version. So, you make an HTTP request to an endpoint. You send the version file as a query parameter from the front end to an endpoint. This endpoint checks if that version file exists on the server. If it does, you send back the contents of the file. Otherwise, you throw an error.

To demonstrate, let's make a v1.txt file in the root directory of your project. Add the following content inside that text file:

App Version 1

Your project structure should look like this:

![Version API Back-End Project Structure.](https://images.ctfassets.net/nx13ojx82pll/ATjP3tLqD71iXMyHdL1kw/5c1b0ac97b01e0c206bb17a069210692/react-command-injection-examples-and-prevention-picture-2.png?w=1012&h=956&q=80&fm=webp)

If you now make a request to http://localhost:8080/?versionFile=v1.txt endpoint, you'll get back the following response:

![Version API Response.](https://images.ctfassets.net/nx13ojx82pll/6w7Zidlq5FYproMakObi4U/ad3778cae7a7e3469a8c528673c53830/react-command-injection-examples-and-prevention-picture-3.png?w=1800&h=434&q=80&fm=webp)

### Consume Version API on Front End

Rewrite your App.js file

In the code, I simply invoke a method that makes an HTTP GET request to the server at the http://localhost:8080/?versionFile=v1.txt endpoint. I call this function inside the useEffect so that it's fired as soon as the page loads. If you check the console, you'll get back the app version in response as shown

![Version API Front End.](https://images.ctfassets.net/nx13ojx82pll/1UPVe0LcOPNU72QeO2QBLb/eb0a46f984a02151a8b27c3947184f55/react-command-injection-examples-and-prevention-picture-4.png?w=1737&h=268&q=80&fm=webp)

### Command Injection Vulnerability

Until now, it may seem as if everything is fine. There's a server that serves an endpoint for version check and your React app makes a request to it. However, the endpoint exposes a command injection vulnerability. Let's see how.

The front end hits the version endpoint with a query parameter that executes a shell command on the server. The query parameter is the file name that contains the version of the app. It's extracted by your server and is directly taken to execute a command. An attacker could easily infiltrate this request and send some malicious commands that can be executed on the server.

Let's say we also had a secrets folder that contains all the sensitive configurational credentials of our project. An attacker could make a request like this from the front end:

const response=await fetch('http://localhost:8080/?versionFile=v1.txt&&cd%20secrets',{mode:'cors'});
which would then execute the following command on the server:

```console
type v1.txt && cd secrets
```

Now the attacker can access your secrets folder! This is just a simple example, but there are a ton of dangerous commands an attacker can execute. [Here's a detailed guide](https://auth0.com/blog/preventing-command-injection-attacks-in-node-js-apps/#A-Realistic-Attack) that tells you all the realistic attacks the attacker can commit using command injection once your system is compromised. For now, let's move ahead and see how we can fix this problem.

### Prevent Command Injection Attack

There are several methods, best practices, and coding guidelines you can follow to prevent a command injection attack on your application. Let's have a look at some of the methods below, what they do and how they combat command injection.

#### Refactor Your API

If you head back to the back-end code, the following lines of code are the bottlenecks for the command injection vulnerability in your system:

```js
const appVersionFile = req.query.versionFile;
const command = `type ${appVersionFile}`;
```

We're directly getting the file name as a query parameter in the API. We're then using this file name directly in the command. Thus, any infiltration with the query parameter is directly going to affect the shell command executed on the server. Besides, it doesn't make a lot of sense to send a hardcoded file name as a query parameter from the front end.

Let's refactor the above lines of code to the following:

```js
const appVersion = req.query.version;
const versionFile = `v${appVersion}.txt`;
const command = `type ${versionFile}`;
```

We have changed the query parameter to be only the version number that we need to check. This is because we don't really need an entire file name as a query parameter in the API. We then use the version number to dynamically generate a version file name. Finally, we use that filename to execute a command. If you now make the same request as earlier, you'll get an error with the following:

```json
{
  "killed": false,
  "code": 1,
  "signal": null,
  "cmd": "type vundefined.txt"
}
```

Similarly, if the attacker tries to inject a command in your server through your React app, they won't be able to do so as the API would throw an exception.
Hence, the attacker won't be able to run any lethal shell commands.

Use More Airtight Functions for Executing Shell Commands
We use the exec function to execute the shell commands. According to NodeJS official docs, this function takes in a command that runs it as it is, "with space-separated arguments." Instead, you can use a more airtight function that disallows your server to run arbitrary commands.

The execFile function takes in a file that contains some shell commands. Additionally, it also takes some arguments to run those commands. It's more secure as now you don't generate commands on the fly. Instead, you store them inside a bash file and can send some arguments specific to the command you want to execute. You can read more about this function [here](https://nodejs.org/api/child_process.html#child_process_child_process_execfile_file_args_options_callback).

### Validate Input

I can't emphasize enough how important it is to validate inputs from the front end. In this scenario, you can validate the query parameters before sending them to the server. Have a look at the following code

```js
const validateQueryParam = (queryParam) => {
  const infiltratedParams = queryParam.split("&&");
  console.log(infiltratedParams);
  if (infiltratedParams.length > 1) return false;
  else return true;
};

const getAppVersion = async () => {
  const queryParam = "versionFile=v1.txt&&cd%20secrets";
  const isValidQueryParam = validateQueryParam(queryParam);
  if (!isValidQueryParam) {
    alert("invalid query params");
    return;
  }
  const response = await fetch(`http://localhost:8080/?${queryParam}`, {
    mode: "cors",
  });
  const data = await response.json();
  console.log(data);
};
```

The above code validates the query parameters on the front end before sending them in the request. The validateQueryParam function checks if the query parameters are infiltrated. If this function returns true, the front end blocks the API request and throws an alert.

You can also validate the query parameters against a more robust regular expression.

# CORS

CORS stands for cross-origin resource sharing. Just like HTTPS, it's a protocol that defines some rules for sharing resources from a different origin. We know that modern web apps consist of two key components: a client and a server. The client requests some data from the server, and the server sends back data as a response.

![Client-server request response.](https://images.ctfassets.net/nx13ojx82pll/3rBFP0LGueb25YZDsL7R1Q/ef91399198a7c4245b0452f0edf70d99/react-cors-guide-what-it-is-and-how-to-enable-it-picture-1.png?w=1372&h=1150&q=80&fm=webp)

This architecture is popular these days because it allows your back end to be used independently across multiple clients like a web app, a desktop GUI, or a native application.

## The Same-Origin Policy

Since the client and server are separate applications, they're usually hosted on different domains. Therefore, your own client that's requesting data from your own server might have different origins. In another scenario, you might use some third-party services for authentication, analytics, etc. The bottom line is that at some point you are going to interact with an application with a different origin than yours. This means you're going to request resources from the application by making an HTTP request.

![Browser's same-origin policy.](https://images.ctfassets.net/nx13ojx82pll/yFNBCE2O76qQZ6qD0hPFG/b8ccd2139f848b881c63f08c5d7ec772/react-cors-guide-what-it-is-and-how-to-enable-it-picture-2.png?w=1000&h=1500&q=80&fm=webp)

When you request a resource from an application of a different origin, the web browser uses an SOP (same-origin policy) protocol to block all your requests to that origin. Back in the day, this is what made the Internet secure! For instance, a malicious cracker or hacker from xyz.com wouldn't be able to access your information on abcbank.com. However, this underlying security rule governing browsers does not allow you to request a resource from a different origin. That's a common use case widely used across web apps today. So what's the solution?

## Enter CORS

CORS enables you to access a resource from a different origin. It is used to override your browser's default behavior due to SOP. So now when your client requests a resource, the response will additionally contain a stamp that tells your browser to allow resource sharing across different origins.

![Client-server request response with CORS enabled.](https://images.ctfassets.net/nx13ojx82pll/5WKTY2QqHenFHlNFcnyq7d/23b3a207efe7c9ab47dbd3b1376cc63e/react-cors-guide-what-it-is-and-how-to-enable-it-picture-3.png?w=1244&h=960&q=80&fm=webp)

Once your browser identifies this stamp, responses for requests from different origins are allowed to pass through. That's precisely what CORS is, and I hope you understand enough to see it in action. If you wish to learn more about it, [click here](https://www.stackhawk.com/blog/what-is-cors/).

## Create Express Server With API Endpoints

In order to enable CORS, you need to create

- A client that can request resources from a server
- A server with some endpoints that can send a response back to the client

Needless to say, both client and server should be running on different domains or have different origins. We can use React to create a simple client that requests resources from a server. However, we first need a server that can serve as an endpoint the client can request a resource from.

Let's create a simple server using Express with some API endpoints. Inside the directory of your choice, run the following command:

```console
mkdir cors-server && cd cors-server
```

You should now have an empty folder named cors-server. Let's initialize a new npm project inside it by running

```console
npm init -y
```

You should now have a package.json file inside the project. Great! Let's install Express, a lightweight NodeJS framework for creating web applications.

```console
npm i express
```

Next, create an app.js file inside the root directory and add the following code to it:

```js
const express = require("express");
const app = express();
app.get("/", (req, res) => {
  res.send("Welcome to CORS server 😁");
});
app.get("/cors", (req, res) => {
  res.send("This has CORS enabled 🎈");
});
app.listen(8080, () => {
  console.log("listening on port 8080");
});
```

In the above code, I have created a minimal server using Express that listens on port 8080. I have two routes, the / and /cors that sends a response.

Let's run our server using the following command:

```console
node app
```

If you point your browser to http://localhost:8080/, you should see something like this:

![Express Server Endpoint.](https://images.ctfassets.net/nx13ojx82pll/6c8teIrh9ae3COBkjveEuu/01e1943f2f0adb9366b54c6fe7e48bc4/react-cors-guide-what-it-is-and-how-to-enable-it-picture-4.png?w=1586&h=210&q=80&fm=webp)

And if you visit http://localhost:8080/cors, you should see something like this:

![Express Server Endpoint /cors.](https://images.ctfassets.net/nx13ojx82pll/6EtmflHkEOFRMtlo25zPLT/3331ec993be93b6e2f571fb946a606c7/react-cors-guide-what-it-is-and-how-to-enable-it-picture-5.png?w=1600&h=194&q=80&fm=webp)

## Set Up React App

Now that we have a server up and running, let's set up a simple React app where we can make requests to our server. Create an empty React App by running

```console
npx create-react-app react-cors-guide
```

Head over to your App.js and replace it with the following:

```js
import { useEffect, useState } from "react";
import "./App.css";
function App() {
  const makeAPICall = async () => {
    try {
      const response = await fetch("http://localhost:8080/", { mode: "cors" });
      const data = await response.json();
      console.log({ data });
    } catch (e) {
      console.log(e);
    }
  };
  useEffect(() => {
    makeAPICall();
  }, []);
  return (
    <div className="App">
      <h1>React Cors Guide</h1>
    </div>
  );
}
export default App;
```

In the above code, I have a function makeAPICall that is invoked when our <App> component mounts on the DOM. Inside the makeAPCall function, I make a GET request to the endpoint http://localhost:8080/ using the Fetch API.

If you open the browser and check your console, instead of the response from the endpoint you'll see an error that looks like this:

![CORS error.](https://images.ctfassets.net/nx13ojx82pll/7ePL8uJ1y5wVpUA4qMvKCl/b996a8ec1a0638995e155314653f221b/react-cors-guide-what-it-is-and-how-to-enable-it-picture-6.png?w=1574&h=753&q=80&fm=webp)

The above is the typical CORS error that occurs because your browser is blocking requests to your server. Even though both your client and the server are running from localhost, your server is hosted on the port 8080 and your React client on port 3000. Therefore, both have a different origin, and the browser's SOP policy comes into play. Let's dive deeper into this CORS error and see a server-side solution to fix this problem.

## CORS Should Always Be Handled From Server Side!

Let's have a closer look at the above CORS error.

```console
Access to fetch at 'http://localhost:8080/' from origin 'http://localhost:3000'
has been blocked by CORS policy: No 'Access-Control-Allow-Origin' header is
present on the requested resource. If an opaque response serves your needs,
set the request's mode to 'no-cors' to fetch the resource with CORS disabled.
```

It states that there's a missing Access-Control-Allow-Origin header on the resource you requested. If you think about it, your client doesn't have anything to do with CORS. It's only something that your browser imposes, and it suggests that your requested resource should be configured differently.

Therefore, it makes sense to configure the response from the server in such a way that the browser identifies this as a CORS request. Hence, logically, CORS should always be handled from the server side. Later we'll explore a way to work around this on the client side, but the most reliable solution is to always make the response from the server CORS-friendly.

## Enable CORS on Server Side

Let's head back to our server's app.js file.

```js
app.get("/cors", (req, res) => {
  res.set("Access-Control-Allow-Origin", "*");
  res.send({ msg: "This has CORS enabled 🎈" });
});
```

Inside the request middleware callback, I first set the Access-Control-Allow-Origin header to an asterisk. The asterisk indicates that this resource can be requested by any client. Let's also change the endpoint in our React app.

```js
const response = await fetch("http://localhost:8080/cors", { mode: "cors" });
```

Now inspect the console.

![CORS enabled.](https://images.ctfassets.net/nx13ojx82pll/6CLtVY9zWJxsZfQajcp0Rj/06d156eca94d1f9d41a607b1001bcc05/react-cors-guide-what-it-is-and-how-to-enable-it-picture-7.png?w=1526&h=746&q=80&fm=webp)

Notice that the CORS error goes away and that you get back the response along with some JSON data. Everything works as intended. Great! All you needed to do was to attach that CORS stamp on your response. Note that you may need to restart your back-end server to see the above changes in action.

You can also set the Access-Control-Allow-Origin to specific domains instead of the asterisk. For instance, setting it to http://localhost:3000 will only enable CORS for clients that are running on the specified URL, localhost:3000.

```js
app.get("/cors", (req, res) => {
  res.set("Access-Control-Allow-Origin", "http://localhost:3000");
  res.send({ msg: "This has CORS enabled 🎈" });
});
```

While the server-side fix to CORS is the most technically coherent solution to this problem, there's a small catch. It requires you to make modifications on the server side. In some cases, you might not have access to server-side code.

For example, if you're using a third-party service for authentication, notification, sending emails, etc., you might run into this problem. In such cases, there isn't much you can do but shoot an email to the developers asking them to enable CORS for your app. There's a neat trick specific to React apps that you can use to work around this problem. Let's see how it works.

## Proxy Requests in a React App

Have you ever tried to proxy your classmate during a lecture by shouting out to their roll call? That's how proxying works in API requests as well! You can tell your React app to proxy your requests to a server using the proxy property inside the package.json file.

This is a simple one-step process. Go inside your app's package.json file and add the following property:

```json
{
...
"proxy":"http://localhost:8080"
...
}
```

Now if you restart your React development server, you'll notice that all requests are being served to http://localhost:8080 instead of http://localhost:3000. You've proxied your React development server to your back-end server. The above works exactly the same way for third-party services as well.

Under the hood, when your React app requests resources from http://localhost:8080, it pretends to be requesting this resource from the origin http://localhost:8080 instead of http://localhost:3000. This seems in line with browser's SOP, and you no longer get the CORS error.
Let's say you're using a service on https://randomservice.com and you come across the CORS error. You can add the URL inside the proxy property in your package.json file.

```json
{
...
"proxy":"https://randomservice.com"
...
}
```

The development server will only attempt to send requests without text/html in its Accept header to the proxy.

Thus for the above method to work, you need to ensure that the server doesn't have text/html in its Accept header. In rare cases, you might need to specify more than one proxy URL. You can set up a proxy manually using a package http-proxy-middleware
