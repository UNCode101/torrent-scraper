# !/usr/bin/env python
# scraper.py
import binascii
import hashlib
import logging
import random
import socket
import struct
import time
from multiprocessing import Pool
from typing import Any, Callable, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs

import requests

from torrent_tracker_scraper import bencode

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Protocol says to keep it that way (https://www.bittorrent.org/beps/bep_0015.html)
PROTOCOL_ID = 0x41727101980
# Scrape response offset, first 8 bytes (4 bytes action, 4 bytes connection_id)
OFFSET = 8
# Scrapre response start infohash data
SCRAPE_RESPONSE_BORDER_LEFT: Callable[[int], int] = lambda i: OFFSET + (i * 12) - 12
# Scrapre response end infohash data
SCRAPE_RESPONSE_BORDER_RIGHT: Callable[[int], int] = lambda i: OFFSET + (i * 12)
# UDP Packet Buffer Size
UDP_PACKET_BUFFER_SIZE = 512


class TRACKER_ACTION:
    CONNECT = 0
    SCRAPE = 2


def is_infohash_valid(infohash: str) -> bool:
    """
    Checks if the infohash is 20 bytes long, confirming its truly of SHA-1 nature

    Args:
    - infohash: Infohash to check

    Returns:
    - bool: True if infohash is valid, False otherwise
    """
    if not isinstance(infohash, str):
        return False

    if len(infohash) == 40:
        return True
    return False


def filter_valid_infohashes(infohashes: list[str]) -> list[str]:
    """Returns a list of valid infohashes"""
    return list(i for i in infohashes if is_infohash_valid(i))


def is_not_blank(s: str) -> bool:
    return bool(s and s.strip())


def get_transaction_id() -> int:
    return random.randrange(1, 65535)


def log_and_set_error(result: dict[str, Any], msg: str):
    logger.error(msg)
    result["error"] = msg


class Connection:
    def __init__(self, hostname, port, timeout: int = 10):
        """
        Connection object to connect to a tracker

        Args:
        - hostname (str): Hostname of the tracker
        - port (int): Port of the tracker
        - timeout (int, optional): Timeout value in seconds, program exits if no response received within this period. Defaults to 10.
        """
        self.hostname = hostname
        self.port = port
        self.sock = self.connect(timeout)

    def __str__(self) -> str:
        return f"{self.hostname}:{self.port}"

    def connect(self, timeout):
        """
        Connects to a tracker and returns a socket object

        Args:
        - timeout (int): Timeout value in seconds, program exits if no response received within this period

        Returns:
        - socket.socket: Socket object
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.connect((self.hostname, self.port))
        except OSError as e:
            sock.close()
            logger.warning("Could not connect to %s: %s", self, e)
            return None
        return sock

# TODO: Add support for HTTP trackers
class Scraper:
    def __init__(
        self,
        infohashes: List[str] | str,
        trackers: Optional[List[str] | str] = None,
        timeout: int = 10,
    ):
        """
        Infohash Scraper to get 'seeders', 'leechers' and 'downloaded' counts for UDP trackers that support the UDP Tracker Protocol (https://www.bittorrent.org/beps/bep_0015.html)

        Args:
            - infohashes (List[str] | str): List of infohashes (or a comma seperated string) to scrape, either from magnet URI or the SHA-1 representation of the ```info``` key in the torrent file. Ex: '95105D919C10E64AE4FA31067A8D37CCD33FE92D'
            - trackers (Optional[List[str]], optional): List of trackers to scrape. If not passed, it will get the list of trackers from newtrackon.com API. Defaults to None.
            - timeout (int, optional): Timeout value in seconds, program exits if no response received within this period. Defaults to 10.

        Example 1:
            Scrape a list of trackers for a list of infohashes and get detailed results for each tracker
            >>> from scraper import Scraper
            >>> scraper = Scraper(
                    infohashes=[
                        "9ecd4676fd0f0474151a4b74a5958f42639cebdf",
                        "75439d5de343999ab377c617c2c647902956e282",
                    ],
                    trackers=[
                        "udp://tracker.openbittorrent.com:80/announce",
                        "udp://tracker.opentrackr.org:1337/announce",
                    ],
                    timeout=5)
            >>> scraper.scrape()
            # Output:
            [{'tracker': 'udp//:tracker.openbittorrent.com:80', 'results': [{'infohash': '9ecd4676fd0f0474151a4b74a5958f42639cebdf', 'seeders': 18, 'completed': 10, 'leechers': 0}, {'infohash': '75439d5de343999ab377c617c2c647902956e282', 'seeders': 24, 'completed': 10, 'leechers': 0}], 'error': None}, {'tracker': 'udp//:tracker.opentrackr.org:1337', 'results': [{'infohash': '9ecd4676fd0f0474151a4b74a5958f42639cebdf', 'seeders': 49, 'completed': 583, 'leechers': 1}, {'infohash': '75439d5de343999ab377c617c2c647902956e282', 'seeders': 87, 'completed': 1119, 'leechers': 1}], 'error': None}]

        Example 2:
            Scrape a list of trackers for a list of infohashes and get combined results by infohashes for all trackers
            >>> from scraper import Scraper
            >>> scraper = Scraper(
                    infohashes="9ecd4676fd0f0474151a4b74a5958f42639cebdf, 75439d5de343999ab377c617c2c647902956e282",
                    trackers="udp://tracker.openbittorrent.com:80/announce, udp://tracker.opentrackr.org:1337/announce",
                    timeout=5)
            >>> scraper.scrape2()
            # Output:
            [{'infohash': '9ecd4676fd0f0474151a4b74a5958f42639cebdf', 'seeders': 49, 'completed': 583, 'leechers': 1},
             {'infohash': '75439d5de343999ab377c617c2c647902956e282', 'seeders': 87, 'completed': 1119, 'leechers': 1}]
        """
        self.trackers = self.get_parsed_trackers(trackers)
        if isinstance(infohashes, str):
            self.infohashes = infohashes.split(",")
        elif isinstance(infohashes, list):
            self.infohashes = infohashes
        self.timeout = timeout

        self.good_infohashes = self.get_good_infohashes()

    def get_good_infohashes(self) -> list[str]:
        """
        Returns a list of valid infohashes

        Returns:
            - list[str]: List of valid infohashes
        """
        if getattr(self, "good_infohashes", None):
            return self.good_infohashes

        good_infohashes = []
        if isinstance(self.infohashes, str):
            infohashes_list = self.infohashes.split(",")
            good_infohashes = filter_valid_infohashes(infohashes_list)
        elif isinstance(self.infohashes, list):
            good_infohashes = filter_valid_infohashes(self.infohashes)
        else:
            logger.error(
                "Infohashes are not supported in type: %s. Only list of strings or comma separated string.",
                type(self.infohashes),
            )
        return good_infohashes

    def get_common_trackers(self) -> list[str]:
        """
        Returns a list of common trackers from newtrackon.com API

        Returns:
            - list[str]: List of common trackers
        """
        response = requests.get("https://newtrackon.com/api/udp")
        trackers = [
            line.strip()
            for line in response.text.splitlines()
            if line.strip().startswith("udp://")
        ]
        trackers = trackers[:10] # limit to 10 trackers
        return trackers

    def get_parsed_trackers(
        self, trackers: Optional[list[str] | str] = None
    ) -> list[Any]:
        """
        Parses trackers and returns a list of parsed trackers

        Args:
            - trackers (list[str] | str, optional): List of trackers. Defaults to None.

        Returns:
            - List[ParseResult]: List of valid UDP trackers parsed using urlparse
        """
        # Check if trackers are passed, else get common trackers
        if trackers is None:
            trackers = self.get_common_trackers()
        else:
            if isinstance(trackers, str):
                trackers = trackers.split(",")
            if isinstance(trackers, list):
                trackers = trackers
            trackers = list(filter(is_not_blank, trackers))
        trackers = [tracker for tracker in trackers if tracker.startswith("udp://")]
        if len(trackers) == 0:
            logger.warn("No valid trackers found, using common trackers")
            trackers = self.get_common_trackers()
        # Parse trackers using urlparse and return
        return [urlparse(tracker) for tracker in trackers]

    def __connect_request(self, transaction_id: int) -> Tuple[int, int, Optional[str]]:
        """
        Sends a connect request and returns a tuple of transaction_id, connection_id and error

        Args:
            - transaction_id (int): Transaction id

        Returns:
            - Tuple[int, int, Optional[str]]: Tuple of transaction_id, connection_id and error
        """
        # Send a Connect Request
        if self.connection.sock is None:
            return 0, 0, "Socket connection is not established."

        packet = struct.pack(
            ">QLL", PROTOCOL_ID, TRACKER_ACTION.CONNECT, transaction_id
        )
        self.connection.sock.send(packet)
        # Receive a Connect Request response
        try:
            res = self.connection.sock.recv(UDP_PACKET_BUFFER_SIZE)
        except OSError as e:
            logger.error("Receiving connect request response failed: %s", e)
            return 0, 0, f"Receiving connect request response failed: {e}"
        # Unpack Connect Request response
        try:
            _, response_transaction_id, connection_id = struct.unpack(">LLQ", res[:16])
        except struct.error as e:
            logger.error("Unpacking connect request response failed: %s", e)
            return 0, 0, f"Unpacking connect request response failed: {e}"

        return int(response_transaction_id), int(connection_id), None

    def __get_packet_hashes(self) -> bytearray:
        """
        Returns a bytearray of infohashes

        Returns:
            - bytearray: bytearray of infohashes
        """
        packet_hashes = bytearray(str(), "utf-8")
        for infohash in self.good_infohashes:
            try:
                packet_hashes += binascii.unhexlify(infohash)
            except binascii.Error as e:
                logger.warning(
                    "Infohash %s is invalid. Error when preparing packet hashes: %s",
                    infohash,
                    e,
                )

        return packet_hashes

    def __scrape_response(
        self, transaction_id: int, connection_id: int
    ) -> Tuple[list[dict[str, Any]], str]:
        """
        Sends a scrape request and returns a list of dicts with infohashes and their stats

        Args:
            - transaction_id (int): Transaction id
            - connection_id (int): Connection id

        Returns:
            - Tuple[list[dict[str, Any]], str]: List of dicts with infohashes and their stats and error
        """
        packet_hashes = self.__get_packet_hashes()
        packet = (
            struct.pack(
                ">QLL",
                connection_id,
                TRACKER_ACTION.SCRAPE,
                transaction_id,
            )
            + packet_hashes
        )
        if self.connection.sock is not None:
            self.connection.sock.send(packet)
        else:
            return [], "Socket connection is not established."

        # Scrape response
        try:
            res = self.connection.sock.recv(UDP_PACKET_BUFFER_SIZE)
            res = res[: 8 + (12 * len(self.good_infohashes))]
        except (socket.timeout, OSError) as e:
            logger.error("Receiving scrape response failed %s: %s", self.connection, e)
            return [], f"Receiving scrape response failed {self.connection}: {e}"

        results: list[dict[str, Any]] = []
        for i, infohash in enumerate(self.good_infohashes, start=1):
            result = {
                "infohash": infohash,
            }

            response = res[
                SCRAPE_RESPONSE_BORDER_LEFT(i) : SCRAPE_RESPONSE_BORDER_RIGHT(i)
            ]
            if len(response) != struct.calcsize(">LLL"):
                result[
                    "error"
                ] = f"Could not get stats for infohash [{self.connection}]"
                results.append(result)
                logger.error("Result error: %s", result)
                continue
            seeders, completed, leechers = struct.unpack(">LLL", response)
            results.append(
                {
                    "infohash": infohash,
                    "seeders": seeders,
                    "completed": completed,
                    "leechers": leechers,
                }
            )

        return results, ""

    def scrape_tracker(self, tracker) -> dict[str, Any]:
        """
        Scrapes a tracker for a list of infohashes
        To understand how data is retrieved visit:
        https://www.bittorrent.org/beps/bep_0015.html

        Args:
            - tracker (str): Tracker url in the format udp://tracker.coppersurfer.tk:6969/announce

        Returns:
            - dict[str, Any]: Dict with tracker, results and error
        """

        logger.debug("Connecting to [%s]", tracker.netloc)
        self.connection = Connection(tracker.hostname, tracker.port, self.timeout)
        tracker_url = f"{tracker.scheme}//:{tracker.netloc}"
        result = {"tracker": tracker_url, "results": [], "error": None}
        # Quit scraping if there is no connection
        if self.connection.sock is None:
            msg = "Socket connection is not established."
            log_and_set_error(result, msg)
            return result

        # We should get the same value in a response
        transaction_id = get_transaction_id()
        try:
            response_transaction_id, connection_id, error = self.__connect_request(
                transaction_id,
            )
            if error:
                result["error"] = error
                return result
        except ConnectionRefusedError as e:
            msg = "Connection refused for %s: %s" % (self.connection, e)
            log_and_set_error(result, msg)
            return result
        except OSError as e:
            msg = f"Connect request failed for {self.connection}: {e}"
            log_and_set_error(result, msg)
            return result

        if response_transaction_id == 0:
            msg = "Response transaction_id==0 meaning something went wrong during the connect request"
            log_and_set_error(result, msg)
            return result

        if transaction_id != response_transaction_id:
            msg = "Response transaction_id doesnt match in connect request [{}]. Expected {}, got {}".format(
                self.connection, transaction_id, response_transaction_id
            )
            log_and_set_error(result, msg)

            return result

        # holds bad error messages
        _bad_infohashes = list()
        for infohash in self.infohashes:
            if not is_infohash_valid(infohash):
                _bad_infohashes.append({"infohash": infohash, "error": "Bad infohash"})

        results, error = self.__scrape_response(transaction_id, connection_id)
        if error:
            result["error"] = error
            return result
        results += _bad_infohashes
        result["results"] = results
        return result

    def scrape(self) -> list[dict[str, Any]] | None:
        """
        Scrape all trackers and infohashes

        Returns:
            - list[dict[str, Any]] | None: List of dicts with tracker, infohash and their stats

        """

        # print(self.get_good_infohashes())

        if not self.good_infohashes:
            logger.info("Nothing to do. No infohashes passed the checks")
            return None

        logger.info(f"Scraping infohashes: {self.good_infohashes}")

        p = Pool()
        results = p.map_async(self.scrape_tracker, self.trackers)
        p.close()
        while True:
            if results.ready():
                break
            time.sleep(0.3)
        results = list(filter(lambda result: result != [], results.get()))

        return results

    def scrape2(self) -> list[dict[str, str | int]] | None:
        """
        Scrape all trackers and combines results by infohashes

        Returns:
            - list[dict[str, str | int]] | None: List of dicts with infohashes and their stats
        """
        scraped_results = self.scrape()
        final_results: dict[str, dict[str, int]] = {}

        if not scraped_results:
            print("No results")
            return None

        for scraped_result in scraped_results:
            if scraped_result:
                for infohash_result in scraped_result["results"]:
                    infohash = infohash_result["infohash"]
                    if infohash not in final_results:
                        final_results[infohash] = {
                            "seeders": 0,
                            "completed": 0,
                            "leechers": 0,
                        }

                    for key in ["seeders", "completed", "leechers"]:
                        new_value = int(infohash_result.get(key, 0))
                        current_value = final_results[infohash][key]
                        if new_value < 2000:
                            final_results[infohash][key] = max(new_value, current_value)

        final_results_list: list[dict[str, str | int]] = [
            {"infohash": infohash, **data} for infohash, data in final_results.items()
        ]

        return final_results_list


class Torrent:
    def __init__(self, torrent_file: str = "", torrent_url: str = ""):
        """
        Torrent object to parse torrent file or torrent url and get infohash and trackers

        Args:
            - torrent_file (str, optional): Torrent file location. Defaults to "".
            - torrent_url (str, optional): Either a url to a .torrent file or a magnet_uri. Defaults to "".

        """
        self.title: str = ""
        self.infohash: str = ""
        self.size: int = 0
        self.trackers: list[str] = []
        self.downloads: int = 0
        self.seeders: int = 0
        self.leechers: int = 0
        if torrent_file:
            self.__parse_torrent_file(torrent_file)
        elif torrent_url:
            if torrent_url.startswith("magnet:?"):
                self.__parse_magnet(torrent_url)
            else:
                self.__from_url(torrent_url)
        return

    def __from_url(self, url: str):
        """
        Downloads a torrent file from a url and parses it

        Args:
            - url (str): Torrent file url
        """
        r = requests.get(url)
        with open("test.torrent", "wb") as f:
            f.write(r.content)
        self.__parse_torrent_file("test.torrent")
        return

    def __parse_torrent_file(self, torrent_file_location: str = ""):
        """
        Parses a torrent file and sets the object attributes

        Args:
            - torrent_file_location (str, optional): Torrent file location. Defaults to "".
        """
        with open(torrent_file_location, "rb") as fp:
            torrent_dic = bencode.load(fp)
        info_data = torrent_dic.get("info", {})
        self.infohash = hashlib.sha1(bencode.dumps(info_data)).hexdigest()
        self.title = info_data.get("name", "").decode("utf-8")
        size = info_data.get("length", 0)
        if isinstance(size, bytes):
            self.size = int.from_bytes(size, "big")
        trackers = torrent_dic.get("announce-list", [])
        for tracker in trackers:
            if isinstance(tracker, list):
                tracker = tracker[0]
            if isinstance(tracker, bytes):
                tracker = tracker.decode("utf-8")
            if isinstance(tracker, str):
                self.trackers.append(tracker)
        return

    def __parse_magnet(self, magnet_uri: str):
        """
        Parses a magnet uri and sets the object attributes

        Args:
            - magnet_uri (str): Magnet uri
        """
        magnet_params = parse_qs(urlparse(magnet_uri).query)
        self.title = magnet_params.get("dn", [""])[0]
        self.infohash = magnet_params.get("xt", [""])[0].replace("urn:btih:", "")
        self.trackers = magnet_params.get("tr", [])

    def scrape(self):
        """
        Scrapes a list of trackers for the infohash

        Returns:
            - List[dict[str, Any]] | None: List of dicts with tracker, infohash and their stats
        """
        scraper = Scraper(
            infohashes=self.infohash,
            trackers=self.trackers,
            timeout=5,
        )
        return scraper.scrape()

    def scrape2(self):
        """
        Scrapes a list of trackers for the infohash and combines results by infohashes

        Returns:
            - List[dict[str, str | int]] | None: List of dicts with infohashes and their stats
        """
        scraper = Scraper(
            infohashes=self.infohash,
            trackers=self.trackers,
            timeout=5,
        )
        results = scraper.scrape2()
        if results:
            result = results[0]
            self.seeders = int(result["seeders"])
            self.leechers = int(result["leechers"])
            self.downloads = int(result["completed"])
        return results

    @staticmethod
    def get_infohashes_and_trackers(
        torrent_files: List["Torrent"],
    ) -> Tuple[list[str], list[str]]:
        """
        Returns a tuple of infohashes and trackers from a list of Torrent objects

        Args:
            - torrent_files (List[Torrent]): List of Torrent objects

        Returns:
            - Tuple[list[str], list[str]]: Tuple of infohashes and trackers
        """
        infohashes: list[str] = []
        trackers: list[str] = []
        for torrent_file in torrent_files:
            infohashes.append(torrent_file.infohash)
            # add trackers only if they are not already present
            for tracker in torrent_file.trackers:
                if tracker not in trackers:
                    if tracker.startswith("udp://"):
                        trackers.append(tracker)
        return infohashes, trackers
