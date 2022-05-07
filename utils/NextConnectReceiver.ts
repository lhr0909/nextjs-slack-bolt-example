import { NextApiRequest, NextApiResponse } from "next";
import nc, { RequestHandler, NextHandler } from "next-connect";
import rawBody from "raw-body";
import querystring from "querystring";
import crypto from "crypto";
import tsscmp from "tsscmp";
import { Logger, ConsoleLogger, LogLevel } from "@slack/logger";
import {
  InstallProvider,
  CallbackOptions,
  InstallProviderOptions,
  InstallURLOptions,
} from "@slack/oauth";
import App from "@slack/bolt/dist/App";
import {
  ReceiverAuthenticityError,
  ReceiverMultipleAckError,
  ReceiverInconsistentStateError,
  ErrorCode,
  CodedError,
} from "@slack/bolt/dist/errors";
import {
  AnyMiddlewareArgs,
  Receiver,
  ReceiverEvent,
} from "@slack/bolt/dist/types";
import defaultRenderHtmlForInstallPath from "@slack/bolt/dist/receivers/render-html-for-install-path";
import { verifyRedirectOpts } from "@slack/bolt/dist/receivers/verify-redirect-opts";
import { StringIndexed } from "@slack/bolt/dist/types/helpers";
import {
  extractRetryNum,
  extractRetryReason,
} from "@slack/bolt/dist/receivers/http-utils";

// Option keys for tls.createServer() and tls.createSecureContext(), exclusive of those for http.createServer()
const httpsOptionKeys = [
  "ALPNProtocols",
  "clientCertEngine",
  "enableTrace",
  "handshakeTimeout",
  "rejectUnauthorized",
  "requestCert",
  "sessionTimeout",
  "SNICallback",
  "ticketKeys",
  "pskCallback",
  "pskIdentityHint",
  "ca",
  "cert",
  "sigalgs",
  "ciphers",
  "clientCertEngine",
  "crl",
  "dhparam",
  "ecdhCurve",
  "honorCipherOrder",
  "key",
  "privateKeyEngine",
  "privateKeyIdentifier",
  "maxVersion",
  "minVersion",
  "passphrase",
  "pfx",
  "secureOptions",
  "secureProtocol",
  "sessionIdContext",
];

const missingServerErrorDescription =
  "The receiver cannot be started because private state was mutated. Please report this to the maintainers.";

export const respondToSslCheck: RequestHandler<NextApiRequest, NextApiResponse> = (req, res, next) => {
  if (req.body && req.body.ssl_check) {
    res.send('');
    return;
  }
  next();
};

export const respondToUrlVerification: RequestHandler<NextApiRequest, NextApiResponse> = (req, res, next) => {
  if (req.body && req.body.type && req.body.type === "url_verification") {
    res.json({ challenge: req.body.challenge });
    return;
  }
  next();
};

// TODO: we throw away the key names for endpoints, so maybe we should use this interface. is it better for migrations?
// if that's the reason, let's document that with a comment.
export interface NextConnectReceiverOptions {
  signingSecret: string | (() => PromiseLike<string>);
  logger?: Logger;
  logLevel?: LogLevel;
  endpoints?:
    | string
    | {
        [endpointType: string]: string;
      };
  signatureVerification?: boolean;
  processBeforeResponse?: boolean;
  clientId?: string;
  clientSecret?: string;
  stateSecret?: InstallProviderOptions["stateSecret"]; // required when using default stateStore
  redirectUri?: string;
  installationStore?: InstallProviderOptions["installationStore"]; // default MemoryInstallationStore
  scopes?: InstallURLOptions["scopes"];
  installerOptions?: InstallerOptions;
  customPropertiesExtractor?: (request: NextApiRequest) => StringIndexed;
}

// Additional Installer Options
interface InstallerOptions {
  stateStore?: InstallProviderOptions["stateStore"]; // default ClearStateStore
  stateVerification?: InstallProviderOptions["stateVerification"]; // defaults true
  authVersion?: InstallProviderOptions["authVersion"]; // default 'v2'
  metadata?: InstallURLOptions["metadata"];
  installPath?: string;
  directInstall?: boolean; // see https://api.slack.com/start/distributing/directory#direct_install
  renderHtmlForInstallPath?: (url: string) => string;
  redirectUriPath?: string;
  callbackOptions?: CallbackOptions;
  userScopes?: InstallURLOptions["userScopes"];
  clientOptions?: InstallProviderOptions["clientOptions"];
  authorizationUrl?: InstallProviderOptions["authorizationUrl"];
}

/**
 * Receives HTTP requests with Events, Slash Commands, and Actions
 */
export default class NextConnectReceiver implements Receiver {
  private bolt: App | undefined;

  private logger: Logger;

  private processBeforeResponse: boolean;

  private signatureVerification: boolean;

  public router: any;

  public installer: InstallProvider | undefined = undefined;

  public installerOptions?: InstallerOptions;

  private customPropertiesExtractor: (request: NextApiRequest) => StringIndexed;

  public constructor({
    signingSecret = "",
    logger = undefined,
    logLevel = LogLevel.INFO,
    endpoints = { events: "/api/slack/events", commands: "/api/slack/commands", actions: "/api/slack/actions" },
    processBeforeResponse = false,
    signatureVerification = true,
    clientId = undefined,
    clientSecret = undefined,
    stateSecret = undefined,
    redirectUri = undefined,
    installationStore = undefined,
    scopes = undefined,
    installerOptions = {},
    customPropertiesExtractor = (_req) => ({}),
  }: NextConnectReceiverOptions) {
    if (typeof logger !== "undefined") {
      this.logger = logger;
    } else {
      this.logger = new ConsoleLogger();
      this.logger.setLevel(logLevel);
    }

    this.signatureVerification = signatureVerification;
    const bodyParser = this.signatureVerification
      ? buildVerificationBodyParserMiddleware(this.logger, signingSecret)
      : buildBodyParserMiddleware(this.logger);
    const expressMiddleware: RequestHandler<NextApiRequest, NextApiResponse>[] = [
      respondToSslCheck,
      respondToUrlVerification,
      this.requestHandler.bind(this),
    ];
    this.processBeforeResponse = processBeforeResponse;

    const endpointList =
      typeof endpoints === "string" ? [endpoints] : Object.values(endpoints);
    this.router = nc();
    endpointList.forEach((endpoint) => {
      this.router.post(endpoint, ...expressMiddleware);
    });

    this.customPropertiesExtractor = customPropertiesExtractor;

    // Verify redirect options if supplied, throws coded error if invalid
    verifyRedirectOpts({
      redirectUri,
      redirectUriPath: installerOptions.redirectUriPath,
    });

    if (
      clientId !== undefined &&
      clientSecret !== undefined &&
      (installerOptions.stateVerification === false || // state store not needed
        stateSecret !== undefined ||
        installerOptions.stateStore !== undefined) // user provided state store
    ) {
      this.installer = new InstallProvider({
        clientId,
        clientSecret,
        stateSecret,
        installationStore,
        logLevel,
        logger, // pass logger that was passed in constructor, not one created locally
        stateStore: installerOptions.stateStore,
        stateVerification: installerOptions.stateVerification,
        authVersion: installerOptions.authVersion ?? "v2",
        clientOptions: installerOptions.clientOptions,
        authorizationUrl: installerOptions.authorizationUrl,
      });
    }
    // create install url options
    const installUrlOptions = {
      metadata: installerOptions.metadata,
      scopes: scopes ?? [],
      userScopes: installerOptions.userScopes,
      redirectUri,
    };
    // Add OAuth routes to receiver
    if (this.installer !== undefined) {
      const redirectUriPath =
        installerOptions.redirectUriPath === undefined
          ? "/api/slack/oauth_redirect"
          : installerOptions.redirectUriPath;
      const { callbackOptions, stateVerification } = installerOptions;
      this.router.use(redirectUriPath, async (req: NextApiRequest, res: NextApiResponse) => {
        if (stateVerification === false) {
          // when stateVerification is disabled pass install options directly to handler
          // since they won't be encoded in the state param of the generated url
          await this.installer!.handleCallback(
            req,
            res,
            callbackOptions,
            installUrlOptions
          );
        } else {
          await this.installer!.handleCallback(req, res, callbackOptions);
        }
      });

      const installPath =
        installerOptions.installPath === undefined
          ? "/api/slack/install"
          : installerOptions.installPath;
      this.router.get(installPath, async (_req: NextApiRequest, res: NextApiResponse, next: NextHandler) => {
        try {
          const url = await this.installer!.generateInstallUrl(
            installUrlOptions,
            stateVerification
          );
          if (installerOptions.directInstall) {
            // If a Slack app sets "Direct Install URL" in the Slack app configuration,
            // the installation flow of the app should start with the Slack authorize URL.
            // See https://api.slack.com/start/distributing/directory#direct_install for more details.
            res.redirect(url);
          } else {
            // The installation starts from a landing page served by this app.
            const renderHtml =
              installerOptions.renderHtmlForInstallPath !== undefined
                ? installerOptions.renderHtmlForInstallPath
                : defaultRenderHtmlForInstallPath;
            res.send(renderHtml(url));
          }
        } catch (error) {
          next(error);
        }
      });
    }
  }

  private async requestHandler(req: NextApiRequest, res: NextApiResponse): Promise<void> {
    let isAcknowledged = false;
    setTimeout(() => {
      if (!isAcknowledged) {
        this.logger.error(
          "An incoming event was not acknowledged within 3 seconds. Ensure that the ack() argument is called in a listener."
        );
      }
    }, 3001);

    let storedResponse;

    // Handle the actions
    if (req.body.payload) {
      req.body = JSON.parse(req.body.payload)
    }

    const event: ReceiverEvent = {
      body: req.body,
      ack: async (response): Promise<void> => {
        this.logger.debug("ack() begin");
        if (isAcknowledged) {
          throw new ReceiverMultipleAckError();
        }
        isAcknowledged = true;
        if (this.processBeforeResponse) {
          if (!response) {
            storedResponse = "";
          } else {
            storedResponse = response;
          }
          this.logger.debug("ack() response stored");
        } else {
          if (!response) {
            res.send("");
          } else if (typeof response === "string") {
            res.send(response);
          } else {
            res.json(response);
          }
          this.logger.debug("ack() response sent");
        }
      },
      retryNum: extractRetryNum(req),
      retryReason: extractRetryReason(req),
      customProperties: this.customPropertiesExtractor(req),
    };

    try {
      await this.bolt?.processEvent(event);
      if (storedResponse !== undefined) {
        if (typeof storedResponse === "string") {
          res.send(storedResponse);
        } else {
          res.json(storedResponse);
        }
        this.logger.debug("stored response sent");
      }
    } catch (err) {
      const e = err as any;
      if ("code" in e) {
        // CodedError has code: string
        const errorCode = (err as CodedError).code;
        if (errorCode === ErrorCode.AuthorizationError) {
          // authorize function threw an exception, which means there is no valid installation data
          res.status(401).send('');
          isAcknowledged = true;
          return;
        }
      }
      res.status(500).send('');
      throw err;
    }
  }

  public init(bolt: App): void {
    this.bolt = bolt;
  }

  public start(): any {
    return this.router;
  }

  public stop(): Promise<void> {
    return Promise.resolve();
  }
}

export function verifySignatureAndParseRawBody(
  logger: Logger,
  signingSecret: string | (() => PromiseLike<string>)
): RequestHandler<NextApiRequest, NextApiResponse> {
  return buildVerificationBodyParserMiddleware(logger, signingSecret);
}

/**
 * This request handler has two responsibilities:
 * - Verify the request signature
 * - Parse request.body and assign the successfully parsed object to it.
 */
function buildVerificationBodyParserMiddleware(
  logger: Logger,
  signingSecret: string | (() => PromiseLike<string>)
): RequestHandler<NextApiRequest, NextApiResponse> {
  return async (req, res, next) => {
    let stringBody: string;
    // On some environments like GCP (Google Cloud Platform),
    // req.body can be pre-parsed and be passed as req.rawBody here
    const preparsedRawBody: any = (req as any).rawBody;
    if (preparsedRawBody !== undefined) {
      stringBody = preparsedRawBody.toString();
    } else {
      stringBody = (await rawBody(req)).toString();
    }

    // *** Parsing body ***
    // As the verification passed, parse the body as an object and assign it to req.body
    // Following middlewares can expect `req.body` is already a parsed one.

    try {
      // This handler parses `req.body` or `req.rawBody`(on Google Could Platform)
      // and overwrites `req.body` with the parsed JS object.
      req.body = verifySignatureAndParseBody(
        typeof signingSecret === "string"
          ? signingSecret
          : await signingSecret(),
        stringBody,
        req.headers
      );
    } catch (error) {
      if (error) {
        if (error instanceof ReceiverAuthenticityError) {
          logError(logger, "Request verification failed", error);
          return res.status(401).send('');
        }

        logError(logger, "Parsing request body failed", error);
        return res.status(400).send('');
      }
    }

    return next();
  };
}

function logError(logger: Logger, message: string, error: any): void {
  const logMessage =
    "code" in error
      ? `${message} (code: ${error.code}, message: ${error.message})`
      : `${message} (error: ${error})`;
  logger.warn(logMessage);
}

function verifyRequestSignature(
  signingSecret: string,
  body: string,
  signature: string | undefined,
  requestTimestamp: string | undefined
): void {
  if (signature === undefined || requestTimestamp === undefined) {
    throw new ReceiverAuthenticityError(
      "Slack request signing verification failed. Some headers are missing."
    );
  }

  const ts = Number(requestTimestamp);
  // eslint-disable-next-line no-restricted-globals
  if (isNaN(ts)) {
    throw new ReceiverAuthenticityError(
      "Slack request signing verification failed. Timestamp is invalid."
    );
  }

  // Divide current date to match Slack ts format
  // Subtract 5 minutes from current time
  const fiveMinutesAgo = Math.floor(Date.now() / 1000) - 60 * 5;

  if (ts < fiveMinutesAgo) {
    throw new ReceiverAuthenticityError(
      "Slack request signing verification failed. Timestamp is too old."
    );
  }

  const hmac = crypto.createHmac("sha256", signingSecret);
  const [version, hash] = signature.split("=");
  hmac.update(`${version}:${ts}:${body}`);

  if (!tsscmp(hash, hmac.digest("hex"))) {
    throw new ReceiverAuthenticityError(
      "Slack request signing verification failed. Signature mismatch."
    );
  }
}

/**
 * This request handler has two responsibilities:
 * - Verify the request signature
 * - Parse request.body and assign the successfully parsed object to it.
 */
export function verifySignatureAndParseBody(
  signingSecret: string,
  body: string,
  headers: Record<string, any>
): AnyMiddlewareArgs["body"] {
  // *** Request verification ***
  const {
    "x-slack-signature": signature,
    "x-slack-request-timestamp": requestTimestamp,
    "content-type": contentType,
  } = headers;

  verifyRequestSignature(signingSecret, body, signature, requestTimestamp);

  return parseRequestBody(body, contentType);
}

function buildBodyParserMiddleware(logger: Logger): RequestHandler<NextApiRequest, NextApiResponse> {
  return async (req, res, next) => {
    let stringBody: string;
    // On some environments like GCP (Google Cloud Platform),
    // req.body can be pre-parsed and be passed as req.rawBody here
    const preparsedRawBody: any = (req as any).rawBody;
    if (preparsedRawBody !== undefined) {
      stringBody = preparsedRawBody.toString();
    } else {
      stringBody = (await rawBody(req)).toString();
    }
    try {
      const { "content-type": contentType } = req.headers;
      req.body = parseRequestBody(stringBody, contentType);
    } catch (error) {
      if (error) {
        logError(logger, "Parsing request body failed", error);
        return res.status(400).send('');
      }
    }
    return next();
  };
}

function parseRequestBody(
  stringBody: string,
  contentType: string | undefined
): any {
  if (contentType === "application/x-www-form-urlencoded") {
    const parsedBody = querystring.parse(stringBody);

    if (typeof parsedBody.payload === "string") {
      return JSON.parse(parsedBody.payload);
    }

    return parsedBody;
  }

  return JSON.parse(stringBody);
}
