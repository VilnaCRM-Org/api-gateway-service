Feature: Streams through the gateway
  In order to protect streaming endpoints like every other route
  As a customer of a VilnaCRM service
  I want my WebSocket and event streams authorized by the gateway and closed when my right to them ends

  Scenario: Frames and events flow unchanged to a subject holding the keys of the streaming routes
    Given a streaming gateway with a WebSocket route and an SSE route
    And the streaming subject "alice" holds the stream keys without expiry
    When the streaming subject "alice" opens a WebSocket
    And the streaming subject "alice" opens an event stream
    Then the opening answer status of the WebSocket of "alice" should be 101
    And the opening answer status of the event stream of "alice" should be 200
    And a frame sent over the WebSocket of "alice" should come back unchanged
    And the event stream of "alice" should deliver its first event
    And the stream registry should hold 2 streams of the subject "alice"
    And the streams upstream should have received 2 requests

  Scenario: A subject without the key and a request without a token are refused before any upgrade
    Given a streaming gateway with a WebSocket route and an SSE route
    And the streaming subject "carol" holds no stream key
    When the streaming subject "carol" opens a WebSocket
    And a request without a token opens a WebSocket
    Then the opening answer status of the WebSocket of "carol" should be 403
    And the opening answer status of the WebSocket without a token should be 401
    And the stream registry should hold 0 streams of the subject "carol"
    And the streams upstream should have received 0 requests

  Scenario: Streams authorized only by an assignment that expires close with it while another stream stays open
    Given a streaming gateway with a WebSocket route and an SSE route
    And the streaming subject "alice" holds the stream keys through an assignment that expires in 600 seconds
    And the streaming subject "bob" holds the stream keys through an assignment that expires in 600 seconds
    And the streaming subject "bob" also holds the stream keys through an assignment that never expires
    When the streaming subject "alice" opens a WebSocket
    And the streaming subject "alice" opens an event stream
    And the streaming subject "bob" opens a WebSocket
    And 600 seconds pass on the gateway clock
    Then the WebSocket of "alice" should be closed with code 1008
    And the event stream of "alice" should end
    And a frame sent over the WebSocket of "bob" should come back unchanged
    And the stream registry should hold 1 streams of the subject "bob"

  Scenario: Every stream is closed when the proof of the pod is older than the hard bound
    Given a streaming gateway with a WebSocket route and an SSE route
    And the streaming subject "alice" holds the stream keys without expiry
    When the streaming subject "alice" opens a WebSocket
    And the streaming subject "alice" opens an event stream
    And the proof of the gateway ages past the hard bound
    Then the WebSocket of "alice" should be closed with code 1013
    And the event stream of "alice" should end
    And the stream registry should hold 0 streams of the subject "alice"
