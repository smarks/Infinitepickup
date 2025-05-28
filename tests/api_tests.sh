#!/bin/bash

# Card Game API - cURL Tests
# Base URL and authentication setup
BASE_URL="https://api.cardgame.com/v1"
AUTH_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Test UUIDs for consistent testing
DECK_ID="550e8400-e29b-41d4-a716-446655440000"
PLAYER_ID="550e8400-e29b-41d4-a716-446655440001"
HAND_ID="550e8400-e29b-41d4-a716-446655440002"

echo "========================================"
echo "Card Game API cURL Tests"
echo "========================================"

# Test 1: Draw Cards from Deck (Success Case)
echo -e "\n1. Testing Draw Cards - Success Case"
echo "Drawing 5 cards from deck..."
curl -X POST "${BASE_URL}/decks/${DECK_ID}/draw" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${AUTH_TOKEN}" \
  -d '{
    "numberOfCards": 5
  }' \
  -w "\nHTTP Status: %{http_code}\n" \
  -s | jq '.'

# Test 2: Draw Cards from Deck (Edge Case - Draw 1 card)
echo -e "\n2. Testing Draw Cards - Single Card"
echo "Drawing 1 card from deck..."
curl -X POST "${BASE_URL}/decks/${DECK_ID}/draw" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${AUTH_TOKEN}" \
  -d '{
    "numberOfCards": 1
  }' \
  -w "\nHTTP Status: %{http_code}\n" \
  -s | jq '.'

# Test 3: Draw Cards - Error Case (Invalid deck ID)
echo -e "\n3. Testing Draw Cards - Invalid Deck ID"
echo "Attempting to draw from non-existent deck..."
curl -X POST "${BASE_URL}/decks/invalid-deck-id/draw" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${AUTH_TOKEN}" \
  -d '{
    "numberOfCards": 3
  }' \
  -w "\nHTTP Status: %{http_code}\n" \
  -s | jq '.'

# Test 4: Draw Cards - Error Case (Invalid number of cards)
echo -e "\n4. Testing Draw Cards - Invalid Number"
echo "Attempting to draw 0 cards (should fail validation)..."
curl -X POST "${BASE_URL}/decks/${DECK_ID}/draw" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${AUTH_TOKEN}" \
  -d '{
    "numberOfCards": 0
  }' \
  -w "\nHTTP Status: %{http_code}\n" \
  -s | jq '.'

# Test 5: Discard Cards from Hand (Success Case)
echo -e "\n5. Testing Discard Cards - Success Case"
echo "Discarding 2 cards from hand..."
curl -X POST "${BASE_URL}/hands/discard" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${AUTH_TOKEN}" \
  -d '{
    "numberOfCards": 2,
    "hand": {
      "id": "'${HAND_ID}'",
      "deckId": "'${DECK_ID}'",
      "cards": [
        {
          "id": "card-001",
          "cardType": "standard",
          "suit": "hearts",
          "rank": "A",
          "value": 14,
          "imageUrl": "https://example.com/cards/ace_hearts.png"
        },
        {
          "id": "card-002",
          "cardType": "standard",
          "suit": "spades",
          "rank": "K",
          "value": 13,
          "imageUrl": "https://example.com/cards/king_spades.png"
        },
        {
          "id": "card-003",
          "cardType": "joker",
          "suit": "none",
          "rank": "joker",
          "value": 15,
          "imageUrl": "https://example.com/cards/joker.png",
          "specialEffect": "Can substitute for any card"
        }
      ],
      "playerId": "'${PLAYER_ID}'"
    }
  }' \
  -w "\nHTTP Status: %{http_code}\n" \
  -s | jq '.'

# Test 6: Discard Cards - Error Case (Too many cards)
echo -e "\n6. Testing Discard Cards - Too Many Cards"
echo "Attempting to discard more cards than available..."
curl -X POST "${BASE_URL}/hands/discard" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${AUTH_TOKEN}" \
  -d '{
    "numberOfCards": 10,
    "hand": {
      "id": "'${HAND_ID}'",
      "deckId": "'${DECK_ID}'",
      "cards": [
        {
          "id": "card-001",
          "cardType": "standard",
          "suit": "hearts",
          "rank": "A",
          "value": 14,
          "imageUrl": "https://example.com/cards/ace_hearts.png"
        }
      ],
      "playerId": "'${PLAYER_ID}'"
    }
  }' \
  -w "\nHTTP Status: %{http_code}\n" \
  -s | jq '.'

# Test 7: Add Deck to Player (Success Case)
echo -e "\n7. Testing Add Deck to Player - Success Case"
echo "Adding a new deck to player..."
curl -X POST "${BASE_URL}/players/${PLAYER_ID}/decks" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${AUTH_TOKEN}" \
  -d '{
    "id": "550e8400-e29b-41d4-a716-446655440003",
    "name": "Standard 52-Card Deck",
    "cards": [
      {
        "id": "card-ace-hearts",
        "cardType": "standard",
        "suit": "hearts",
        "rank": "A",
        "value": 14,
        "imageUrl": "https://example.com/cards/ace_hearts.png"
      },
      {
        "id": "card-two-hearts",
        "cardType": "standard",
        "suit": "hearts",
        "rank": "2",
        "value": 2,
        "imageUrl": "https://example.com/cards/two_hearts.png"
      },
      {
        "id": "card-joker-red",
        "cardType": "joker",
        "suit": "none",
        "rank": "joker",
        "value": 15,
        "imageUrl": "https://example.com/cards/joker_red.png",
        "specialEffect": "Wild card - can represent any card"
      }
    ],
    "totalCards": 54,
    "isShuffled": false,
    "createdAt": "2025-05-25T10:00:00Z"
  }' \
  -w "\nHTTP Status: %{http_code}\n" \
  -s | jq '.'

# Test 8: Add Deck to Player - Error Case (Player not found)
echo -e "\n8. Testing Add Deck to Player - Player Not Found"
echo "Attempting to add deck to non-existent player..."
curl -X POST "${BASE_URL}/players/non-existent-player/decks" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${AUTH_TOKEN}" \
  -d '{
    "id": "550e8400-e29b-41d4-a716-446655440004",
    "name": "Test Deck",
    "cards": [],
    "totalCards": 0
  }' \
  -w "\nHTTP Status: %{http_code}\n" \
  -s | jq '.'

# Test 9: Shuffle Deck (Success Case)
echo -e "\n9. Testing Shuffle Deck - Success Case"
echo "Shuffling deck..."
curl -X POST "${BASE_URL}/decks/${DECK_ID}/shuffle" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${AUTH_TOKEN}" \
  -w "\nHTTP Status: %{http_code}\n" \
  -s | jq '.'

# Test 10: Shuffle Deck - Error Case (Deck not found)
echo -e "\n10. Testing Shuffle Deck - Deck Not Found"
echo "Attempting to shuffle non-existent deck..."
curl -X POST "${BASE_URL}/decks/non-existent-deck/shuffle" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${AUTH_TOKEN}" \
  -w "\nHTTP Status: %{http_code}\n" \
  -s | jq '.'

# Test 11: Authentication Test - Missing Token
echo -e "\n11. Testing Authentication - Missing Token"
echo "Attempting request without authentication..."
curl -X POST "${BASE_URL}/decks/${DECK_ID}/draw" \
  -H "Content-Type: application/json" \
  -d '{
    "numberOfCards": 1
  }' \
  -w "\nHTTP Status: %{http_code}\n" \
  -s | jq '.'

# Test 12: Authentication Test - Invalid Token
echo -e "\n12. Testing Authentication - Invalid Token"
echo "Attempting request with invalid token..."
curl -X POST "${BASE_URL}/decks/${DECK_ID}/draw" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer invalid-token-12345" \
  -d '{
    "numberOfCards": 1
  }' \
  -w "\nHTTP Status: %{http_code}\n" \
  -s | jq '.'

echo -e "\n========================================"
echo "Tests completed!"
echo "========================================"

# Performance Test - Multiple rapid requests
echo -e "\n13. Performance Test - Multiple Rapid Requests"
echo "Testing multiple draw requests rapidly..."
for i in {1..5}; do
  echo "Request $i..."
  curl -X POST "${BASE_URL}/decks/${DECK_ID}/draw" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${AUTH_TOKEN}" \
    -d '{
      "numberOfCards": 1
    }' \
    -w "Response time: %{time_total}s, HTTP Status: %{http_code}\n" \
    -s -o /dev/null
done

# Test with different card types
echo -e "\n14. Testing Discard with Different Card Types"
echo "Discarding mixed card types..."
curl -X POST "${BASE_URL}/hands/discard" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${AUTH_TOKEN}" \
  -d '{
    "numberOfCards": 3,
    "hand": {
      "id": "'${HAND_ID}'",
      "deckId": "'${DECK_ID}'",
      "cards": [
        {
          "id": "card-standard",
          "cardType": "standard",
          "suit": "diamonds",
          "rank": "Q",
          "value": 12,
          "imageUrl": "https://example.com/cards/queen_diamonds.png"
        },
        {
          "id": "card-wild",
          "cardType": "wild",
          "suit": "none",
          "rank": "wild",
          "value": 0,
          "imageUrl": "https://example.com/cards/wild.png",
          "specialEffect": "Can be any card value"
        },
        {
          "id": "card-action",
          "cardType": "action",
          "suit": "none",
          "rank": "10",
          "value": 10,
          "imageUrl": "https://example.com/cards/action_draw2.png",
          "specialEffect": "Next player draws 2 cards"
        }
      ],
      "playerId": "'${PLAYER_ID}'"
    }
  }' \
  -w "\nHTTP Status: %{http_code}\n" \
  -s | jq '.'

echo -e "\nAll tests completed successfully!"