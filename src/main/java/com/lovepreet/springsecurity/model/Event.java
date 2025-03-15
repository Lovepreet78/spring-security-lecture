package com.lovepreet.springsecurity.model;


import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;
import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "events")
public class Event {
        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        private Long id;

        @JsonProperty("name")
        @Column(nullable = false)
        private String name;

        @JsonProperty("location")
        @Column(nullable = false)
        private String location;

        @JsonProperty("organizer")
        @Column(nullable = false)
        private String organizer;
}
