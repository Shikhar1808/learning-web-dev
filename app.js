const express = require('express');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');

const AppError = require('./utils/appError');
const globalErrorHandler = require('./controllers/errorController');
const tourRouter = require('./routes/tourRoutes');
const userRouter = require('./routes/userRoutes');

const app = express();

// 1) MIDDLEWARES
app.use(helmet());
//Here we are using the helmet middleware to set some security HTTP headers to protect the application from well-known web vulnerabilities. Helmet helps to secure the application by setting various HTTP headers. In this case, we are using the default settings of helmet.
//We should put the helmet middleware at the beginning of the middleware stack to ensure that the headers are set before any other middleware is used.

if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}
//Here we are using the morgan middleware in development mode to log the request method, the url, the status code, the response time and the size of the response body. basically what morgon does is that it logs the request to the console in a nice format.

const limiter = rateLimit({
  max: 100,
  windowMs: 60 * 60 * 1000,
  message: 'Too many requests from this IP, please try again in an hour!',
});

app.use('/api', limiter);
//Here we are using the rateLimit middleware to limit the number of requests that can be made to the server from a single IP address in a given time window. In this case, we are limiting the number of requests to 100 requests per hour. If the number of requests exceeds 100, the server will respond with a status code of 429 and a message of 'Too many requests from this IP, please try again in an hour!'.

app.use(express.json({
  limit: '10kb'  //We are using limit option to limit the size of the request body to 10kb. If the request body is larger than 10kb, the request will be rejected with a status code of 413.
}));

//Data sanitization against NoSQL query injection
app.use(mongoSanitize());
//What this middleware does is that it removes the dollar sign ($) and the dot (.) from the request query. This helps to prevent NoSQL query injection attacks. NoSQL query injection is a type of attack where an attacker sends a query to the database that can reveal sensitive information or modify the data in the database.

//Data sanitization against XSS
app.use(xss());
//What this middleware does is that it removes any HTML tags from the request body. This helps to prevent cross-site scripting (XSS) attacks. Cross-site scripting is a type of attack where an attacker injects malicious scripts into a web page that can steal sensitive information or perform actions on behalf of the user.

//Prevent parameter pollution
app.use(hpp(
  {
    whitelist: ['duration', 'ratingsQuantity', 'ratingsAverage', 'maxGroupSize', 'difficulty', 'price']
  }
));
//What this middleware does is that it removes duplicate parameters from the request query. This helps to prevent parameter pollution attacks. Parameter pollution is a type of attack where an attacker sends multiple parameters with the same name in the request query to override the original parameter value.

app.use(express.static(`${__dirname}/public`));

app.use((req, res, next) => {
  req.requestTime = new Date().toISOString();
  next();
});

// 3) ROUTES
app.use('/api/v1/tours', tourRouter);
app.use('/api/v1/users', userRouter);

app.all('*', (req, res, next) => {
  next(new AppError(`Can't find ${req.originalUrl} on this server!`, 404));
});

app.use(globalErrorHandler);

module.exports = app;
