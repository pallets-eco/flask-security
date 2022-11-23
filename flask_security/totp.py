"""
    flask_security.totp
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security TOTP (Timed-One-Time-Passwords) module

    :copyright: (c) 2019-2021 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.
"""
import base64
import io
import typing as t

from passlib.totp import TOTP, TokenError, TotpMatch
from passlib.pwd import genword

if t.TYPE_CHECKING:  # pragma: no cover
    from .datastore import User


class Totp:
    """Encapsulate usage of Passlib TOTP functionality.

    Flask-Security doesn't implement any replay-attack protection out of the box
    as suggested by:
    https://passlib.readthedocs.io/en/stable/narr/totp-tutorial.html#match-verify

    Subclass this and implement the get/set last_counter methods. Your subclass can
    be registered at Flask-Security creation/initialization time.

    .. versionadded:: 3.4.0

    """

    def __init__(self, secrets: t.Dict[t.Union[str, int], str], issuer: str):
        """Initialize a totp factory.
        secrets are used to encrypt the per-user totp_secret on disk.
        """
        # This should be a dict with at least one entry
        if not isinstance(secrets, dict) or len(secrets) < 1:
            raise ValueError("secrets needs to be a dict with at least one entry")
        self._totp = TOTP.using(issuer=issuer, secrets=secrets)

    def generate_totp_password(self, totp_secret: str) -> str:
        """Get time-based one-time password on the basis of given secret and time
        :param totp_secret: the unique shared secret of the user
        """
        return self._totp.from_source(totp_secret).generate().token

    def generate_totp_secret(self) -> str:
        """Create new user-unique totp_secret.

        We return an encrypted json string so that when sent in a cookie or
        sent to DB - it is encrypted.

        """
        return self._totp.new().to_json(encrypt=True)

    def verify_totp(
        self, token: str, totp_secret: str, user: "User", window: int = 0
    ) -> bool:
        """Verifies token for specific user.

        :param token: token to be check against user's secret
        :param totp_secret: the unique shared secret of the user
        :param user: User model
        :param window: optional. How far backward and forward in time to search
         for a match. Measured in seconds.
        :return: True if match
        """

        # TODO - in old implementation  using onetimepass window was described
        # as 'compensate for clock skew) and 'interval_length' would say how long
        # the token is good for.
        # In passlib - 'window' means how far back and forward to look and 'clock_skew'
        # is specifically for well, clock slew.
        try:
            tmatch = self._totp.verify(
                token,
                totp_secret,
                window=window,
                last_counter=self.get_last_counter(user),
            )
            self.set_last_counter(user, tmatch)
            return True

        except TokenError:
            return False

    def get_totp_uri(self, username: str, totp_secret: str) -> str:
        """Generate provisioning url for use with the qrcode
                scanner built into the app

        :param username: username/email of the current user
        :param totp_secret: a unique shared secret of the user
        """
        tp = self._totp.from_source(totp_secret)
        return tp.to_uri(username)

    def get_totp_pretty_key(self, totp_secret: str) -> str:
        """Generate pretty key for manual input

        :param totp_secret: a unique shared secret of the user

        .. versionadded:: 4.0.0
        """
        tp = self._totp.from_source(totp_secret)
        return tp.pretty_key()

    def fetch_setup_values(self, totp: str, user: "User") -> t.Dict[str, str]:
        """Generate various values user needs to setup authenticator app.
            Returns dict with keys:
                'key': totp key
                'image': image as string (useful for <img src=xx>)
                'username: qrcode best practice
                'issuer': qrcode best practice

        .. versionadded:: 4.0.0
        """

        r = dict()

        # By convention, the URI should have the username that the user
        # logs in with.
        username = user.calc_username() or "Unknown"
        r["username"] = username
        r["key"] = self.get_totp_pretty_key(totp)
        r["issuer"] = self._totp.issuer
        r["image"] = self.generate_qrcode(username, totp)
        return r

    def generate_qrcode(self, username: str, totp: str) -> str:
        """Generate QRcode
         Using username, totp, generate the actual QRcode image.
         This method can be overridden to fine-tune how the image is created -
         such as size, color etc.

         It must return a string suitable for use in an <img src=xx> tag.

        .. versionadded:: 4.0.0
        """
        try:
            import qrcode
            import qrcode.image.svg

            image = qrcode.make(
                self.get_totp_uri(username, totp),
                image_factory=qrcode.image.svg.SvgImage,
            )
            with io.BytesIO() as virtual_file:
                image.save(virtual_file)
                image_as_str = base64.b64encode(virtual_file.getvalue()).decode("ascii")

            return f"data:image/svg+xml;base64,{image_as_str}"
        except ImportError:  # pragma: no cover
            # This should have been checked at app init.
            raise

    def generate_recovery_codes(self, number: int) -> t.List[str]:
        """Generate a set of secure passwords - used for 2FA recovery codes.
            # this is nice for english - but not for others
            return genphrase(entropy="fair", wordset="eff_short", sep="-",
             returns=number)

        .. versionadded:: 5.0.0
        """
        pwds = genword(length=12, charset="hex", returns=number)
        # make this a bit easier to type - 3 sets of 4 characters
        spwds = []
        for pwd in pwds:
            spwds.append(
                "-".join([pwd[i : i + 4] for i in range(0, len(pwd), 4)])  # noqa: E203
            )
        return spwds

    def get_last_counter(self, user: "User") -> t.Optional[TotpMatch]:
        """Implement this to fetch stored last_counter from cache.

        :param user: User model
        :return: last_counter as stored in set_last_counter()
        """
        return None

    def set_last_counter(self, user: "User", tmatch: TotpMatch) -> None:
        """Implement this to cache last_counter.

        :param user: User model
        :param tmatch: a TotpMatch as returned from totp.verify()
        """
        pass
